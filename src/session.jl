# Represents a keyboard-interactive prompt from a server
struct KbdintPrompt
    msg::String
    display::Bool
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

Represents an SSH session. Note that some properties such as the host and port are
implemented in `getproperty()`/`setproperty!()` by using the internal values of
the `ssh_session`, i.e. they aren't simply fields of the struct. A `Session` may
be owning or non-owning of its internal pointer to a `lib.ssh_session`.

!!! warning
    It's *highly recommended* to close `Session`'s explicitly with
    [`Base.close(::Session)`](@ref). Finalizers do not allow task switches so
    the finalizer for `Session` will abruptly kill the session and free its
    memory, which may cause problems in other code relying on the `Session`.
"""
mutable struct Session
    ptr::Union{lib.ssh_session, Nothing}
    owning::Bool
    closeables::Vector{Any}
    server_callbacks::Union{Callbacks.ServerCallbacks, Nothing}

    log_verbosity::Int
    ssh_dir::Union{String, Nothing}
    gssapi_server_identity::Union{String, Nothing}
    process_config::Bool

    _lock::ReentrantLock
    _auth_methods::Union{Vector{AuthMethod}, Nothing}
    _attempted_auth_methods::Vector{AuthMethod}
    _require_init_kbdint::Bool

    # Event to notify the waiter task when someone wants to wait() on the Session
    _waiter_request::Threads.Event
    # Condition for callers to wait() on
    _wakeup::CloseableCondition
    # Tell the waiter task when to stop
    @atomic _waiter_stop_flag::Bool
    # The waiter task runs for as long as the Session is open. Its only job is
    # to wakeup when requested by other tasks calling wait(::Session), poll the
    # Session, and then wakeup all waiting tasks to let them know that they can
    # run their callbacks. It's important that only one task is doing the
    # waiting on the file descriptor, because if there's multiple tasks waiting
    # then one task might 'catch' an event that was intended for some other
    # task.
    _waiter_task::Task

    @doc """
    $(TYPEDSIGNATURES)

    This is only useful if you already have a `ssh_session` (i.e. in a
    server). Do not use it if you want a client, use the host/port constructor.

    # Arguments
    - `ptr`: A pointer to the `lib.ssh_session` to wrap.
    - `log_verbosity=nothing`: Set the log verbosity for the
       session. This argument will be ignored if `own` is `false` to avoid
       accidentally changing the logging level in callbacks when non-owning
       Sessions are created. You can still set the logging level explicitly with
       `session.log_verbosity` if necessary.
    - `own=true`: Whether to take ownership of `ptr`, i.e. whether
      to register a finalizer to free the memory.
    """
    function Session(ptr::lib.ssh_session; log_verbosity=nothing, own::Bool=true)
        # Set to non-blocking mode
        lib.ssh_set_blocking(ptr, 0)

        session = new(ptr, own, [], nothing,
                      -1, nothing, nothing, true,
                      ReentrantLock(), nothing, AuthMethod[], true,
                      Threads.Event(true), CloseableCondition(), false)

        # Start the waiter task
        session._waiter_task = Threads.@spawn _wait_loop(session)
        errormonitor(session._waiter_task)

        if !isnothing(log_verbosity)
            session.log_verbosity = log_verbosity
        end

        if own
            finalizer(_finalizer, session)
        end

        return session
    end
end

function Base.unsafe_convert(::Type{lib.ssh_session}, session::Session)
    if !isassigned(session)
        throw(ArgumentError("Session is unassigned, cannot get a pointer from it"))
    end

    return session.ptr
end

Base.unsafe_convert(::Type{Ptr{Cvoid}}, session::Session) = Ptr{Cvoid}(Base.unsafe_convert(lib.ssh_session, session))

function _safe_getproperty(session::Session, name::Symbol)
    try
        getproperty(session, name)
    catch ex
        if ex isa LibSSHException
            "<unset>"
        else
            rethrow()
        end
    end
end

function Base.show(io::IO, session::Session)
    if isopen(session)
        host = _safe_getproperty(session, :host)
        user = _safe_getproperty(session, :user)

        print(io, Session, "(host=$(host), port=$(session.port), user=$(user), connected=$(isconnected(session)))")
    else
        print(io, Session, "([closed])")
    end
end

Base.lock(session::Session) = lock(session._lock)
Base.unlock(session::Session) = unlock(session._lock)
Base.islocked(session::Session) = islocked(session._lock)
Base.trylock(session::Session) = trylock(session._lock)

# Non-throwing finalizer for Session objects
function _finalizer(session::Session)
    if isopen(session)
        if !trylock(session)
            finalizer(_finalizer, session)
        else
            try
                lib.ssh_free(session)
                session.ptr = nothing
            finally
                unlock(session)
            end
        end
    end
end

"""
$(TYPEDSIGNATURES)

Constructor for creating a client session. Use this if you want to connect to a
server.

!!! warning
    By default libssh will try to follow the settings in any found SSH config
    files. If a proxyjump is configured for `host` libssh will try to set up the
    proxy itself, which usually does not play well with Julia's event loop. In
    such situations you will probably want to pass `process_config=false` and
    set up the proxyjump explicitly using a [`Forwarder`](@ref).

# Throws
- [`LibSSHException`](@ref): if a session couldn't be created, or there was an
  error initializing the `user` property.

# Arguments
- `host`: The host to connect to.
- `port=22`: The port to connect to.
- `socket=nothing`: Can be an open `TCPSocket` or `RawFD` to connect to
  directly. If this is not `nothing` it will be used instead of `port`. You will
  need to close the socket afterwards, the `Session` will not do it for you.
- `user=nothing`: Set the user to connect as. If unset the current
   username will be used.
- `log_verbosity=nothing`: Set the log verbosity for the session.
- `auto_connect=true`: Whether to automatically call
  [`connect()`](@ref).
- `process_config=true`: Whether to process any found SSH config files.

# Examples

```julia-repl
julia> import LibSSH as ssh
julia> session = ssh.Session("foo.org")
julia> session = ssh.Session(ip"12.34.56.78", 2222)
```
"""
function Session(host::Union{AbstractString, Sockets.IPAddr}, port=22;
                 socket::Union{Sockets.TCPSocket, RawFD, Nothing}=nothing,
                 user=nothing, log_verbosity=nothing, auto_connect=true,
                 process_config=true)
    session_ptr = lib.ssh_new()
    if session_ptr == C_NULL
        throw(LibSSHException("Could not initialize Session for host $(host)"))
    end

    host_str = host isa AbstractString ? host : string(host)

    session = Session(session_ptr; log_verbosity)

    # Put this section in a try-catch block so that the session will be free'd
    # if initialization fails for some reason.
    try
        session.host = host_str

        if isnothing(socket)
            session.port = port
        else
            session.fd = socket isa RawFD ? socket : Base._fd(socket)
        end

        if isnothing(user)
            # Explicitly initialize the user, otherwise an error will be thrown when
            # retrieving it. Passing null will set it to the current user (see docs).
            lib.ssh_options_set(session, SSH_OPTIONS_USER, C_NULL)
        else
            session.user = user
        end

        session.process_config = process_config

        if auto_connect
            connect(session)
        end

        return session
    catch
        close(session)
        rethrow()
    end
end

"""
$(TYPEDSIGNATURES)

Do-constructor for [`Session`](@ref). All arguments are forwarded to the other
constructors.
"""
function Session(f::Function, args...; kwargs...)
    session = Session(args...; kwargs...)
    try
        return f(session)
    finally
        close(session)
    end
end

"""
$(TYPEDSIGNATURES)

Check if the `Session` holds a valid pointer to a `lib.ssh_session`. This will
be `false` if the session has been closed.
"""
Base.isassigned(session::Session) = !isnothing(session.ptr)

# Make the Session closed for wait()'ing and wake up any existing waiting
# tasks. This is probably only useful in servers.
function closewait(session::Session)
    # Close the waiter task so it will never notify again
    @atomic session._waiter_stop_flag = true
    notify(session._waiter_request)
    wait(session._waiter_task)

    # Wake up any tasks that were already waiting
    @lock session._wakeup close(session._wakeup)
end

"""
$(TYPEDSIGNATURES)

Closes a session, which will be unusable afterwards. It's safe to call this
multiple times.

# Throws
- `ArgumentError`: If the session is non-owning. This is not allowed to prevent
  accidental double-frees.
"""
function Base.close(session::Session)
    if !session.owning
        throw(ArgumentError("Calling close() on a non-owning Session is not allowed to avoid accidental double-frees, see the docs for more information."))
    end

    @lock session if isopen(session)
        closewait(session)
        disconnect(session)
        lib.ssh_free(session)
        session.ptr = nothing
    end
end

"""
$(TYPEDSIGNATURES)

Check if a session is open.
"""
Base.isopen(session::Session) = isassigned(session) # We currently don't allow closed sessions

"""
$(TYPEDSIGNATURES)

Get the last error set by libssh.

# Throws
- `ArgumentError`: If the session has been closed.

Wrapper around [`lib.ssh_get_error()`](@ref).
"""
function get_error(session::Session)
    if !isassigned(session)
        throw(ArgumentError("Session has been free'd, cannot get its error"))
    end

    ret = lib.ssh_get_error(session)
    return unsafe_string(ret)
end

# Mapping from option name to the corresponding enum and C type
const SESSION_PROPERTY_OPTIONS = Dict(:host => (SSH_OPTIONS_HOST, Cstring),
                                      :port => (SSH_OPTIONS_PORT, Cuint),
                                      :fd => (SSH_OPTIONS_FD, Cint),
                                      :user => (SSH_OPTIONS_USER, Cstring),
                                      :ssh_dir => (SSH_OPTIONS_SSH_DIR, Cstring),
                                      :known_hosts => (SSH_OPTIONS_KNOWNHOSTS, Cstring),
                                      :gssapi_server_identity => (SSH_OPTIONS_GSSAPI_SERVER_IDENTITY, Cstring),
                                      :log_verbosity => (SSH_OPTIONS_LOG_VERBOSITY, Cuint),
                                      :process_config => (SSH_OPTIONS_PROCESS_CONFIG, Bool))
# These properties cannot be retrieved from the libssh API (i.e. with
# ssh_options_get()), so we store them in the Session object instead.
const SAVED_PROPERTIES = (:log_verbosity, :gssapi_server_identity, :ssh_dir, :process_config)

function Base.propertynames(::Session, private::Bool=false)
    fields = fieldnames(Session)
    libssh_options = tuple(keys(SESSION_PROPERTY_OPTIONS)...)

    return (libssh_options..., fields...)
end

function Base.getproperty(session::Session, name::Symbol)
    if name ∉ propertynames(session, true)
        error("type Session has no field $(name)")
    end

    # If it's a property that we save, then we return the saved value
    if name in fieldnames(Session) || name in SAVED_PROPERTIES
        return getfield(session, name)
    end

    # Otherwise, we retrieve it from the ssh_session object
    ret = 0
    value = nothing
    is_string = false

    if name === :port
        # The port is a special option with its own function
        port = Ref{Cuint}(0)
        ret = lib.ssh_options_get_port(session, port; throw=false)
        value = UInt(port[])
    elseif name === :fd
        value = RawFD(lib.ssh_get_fd(session))
    else
        # All properties supported by ssh_options_get() are strings, so we know
        # that this option must be a string.
        is_string = true
        option = SESSION_PROPERTY_OPTIONS[name][1]

        out = Ref{Ptr{Cchar}}()
        ret = lib.ssh_options_get(session, option, out; throw=false)
    end

    if ret != 0
        throw(LibSSHException("Error getting $(name) from session: $(ret)"))
    end

    if is_string
        value = unsafe_string(out[])
        lib.ssh_string_free_char(out[])
    end

    return value
end

function Base.setproperty!(session::Session, name::Symbol, value)
    if name ∉ propertynames(session, true)
        error("type Session has no field $(name)")
    end

    if name in (:ptr, :server_callbacks, :_auth_methods, :_attempted_auth_methods,
                :_kbdint_prompts, :_require_init_kbdint, :_waiter_task, :_waiter_stop_flag)
        return setfield!(session, name, value)
    end

    # There's some weirdness around saving strings, so we do some special-casing
    # here to handle them.
    option, ctype = SESSION_PROPERTY_OPTIONS[name]
    is_string = ctype == Cstring

    # Always convert string values to String, types like SubString cannot be
    # converted to Cstring.
    if is_string
        value_str = String(value)
        GC.@preserve value_str begin
            cvalue = Base.unsafe_convert(ctype, value_str)
            ret = lib.ssh_options_set(session, option, Ptr{Cvoid}(cvalue); throw=false)
        end
    else
        GC.@preserve value begin
            cvalue = Base.cconvert(ctype, value)
            ret = lib.ssh_options_set(session, option, Ref(cvalue); throw=false)
        end
    end

    if ret != 0
        throw(LibSSHException("Error setting Session.$(name) to $(value): $(ret)"))
    end

    # Some properties cannot be retrieved from the libssh API, so we also save
    # them explicitly in the Session.
    if name in SAVED_PROPERTIES
        saved_type = fieldtype(Session, name)
        converted_value = saved_type isa Union ? value : saved_type(value)
        setfield!(session, name, converted_value)
    end

    return value
end

# Helper macro to lock a session and temporarily set it to blocking mode while
# executing some expression.
macro lockandblock(session, expr)
    quote
        @lock $(esc(session)) begin
            lib.ssh_set_blocking($(esc(session)), 1)

            try
                $(esc(expr))
            finally
                lib.ssh_set_blocking($(esc(session)), 0)
            end
        end
    end
end

"""
$(TYPEDSIGNATURES)

Waits for data to be readable/writable on a session.

# Throws
- `InvalidStateException`: If the session is already closed, or is closed while
  waiting.
"""
function Base.wait(session::Session)
    if !isopen(session)
        throw(InvalidStateException("Session is closed, cannot wait() on it", :closed))
    end

    @lock session._wakeup begin
        # Tell the waiter task we want the session to be polled
        notify(session._waiter_request)

        wait(session._wakeup)
    end
end

# This is run for as long as the session is open
function _wait_loop(session::Session)
    while isopen(session)
        wait(session._waiter_request)
        if @atomic session._waiter_stop_flag
            break
        end

        poll_flags = lib.ssh_get_poll_flags(session)
        readable = (poll_flags & lib.SSH_READ_PENDING) > 0
        writable = (poll_flags & lib.SSH_WRITE_PENDING) > 0

        while !(@atomic session._waiter_stop_flag) && isopen(session)
            result = @lock session _safe_poll_fd(session.fd, 0.1; readable, writable)
            if isnothing(result)
                # This means the session's file descriptor has been closed (see the
                # comments for _safe_poll_fd()).
                break
            elseif !result.timedout
                # Wakeup waiting tasks
                @lock session._wakeup notify(session._wakeup)
                break
            else
                # Ugly hack to allow other tasks to take the lock. See the
                # comments in `listen()` in server.jl.
                sleep(0.001)
            end
        end
    end

    return nothing
end

"""
$(TYPEDSIGNATURES)

This will throw an exception if connecting fails. You shouldn't need this unless
you've created a session with `Session(; auto_connect=false)`.

Wrapper around [`lib.ssh_connect()`](@ref).
"""
function connect(session::Session)
    if !isassigned(session)
        throw(ArgumentError("Session has been closed, cannot connect it to a server"))
    elseif isconnected(session)
        return
    end

    while true
        ret = lib.ssh_connect(session)

        if ret == SSH_AGAIN
            wait(session)
        elseif ret == SSH_OK
            break
        else
            throw(LibSSHException("Error connecting to $(session.host) (port $(session.port)): $(get_error(session))"))
        end
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around [`lib.ssh_disconnect()`](@ref).

!!! warning
    This will close all channels created from the session.
"""
function disconnect(session::Session)
    @lock session if isconnected(session)
        # We close all the closeables in reverse order because closing them will
        # delete each object from the vector and we don't want to invalidate any
        # indices while deleting. The channels in particular need to be closed
        # here because lib.ssh_disconnect() will free all of them.
        for i in reverse(eachindex(session.closeables))
            # Note that only owning channels are added to session.closeables, which
            # means that this should never throw because the channel is non-owning
            # (of course it may still throw for other reasons).
            close(session.closeables[i])
        end

        lib.ssh_disconnect(session)
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around [`lib.ssh_is_connected()`](@ref).
"""
function isconnected(session::Session)
    isassigned(session) ? lib.ssh_is_connected(session) == 1 : false
end

"""
$(TYPEDSIGNATURES)

Get the public key from server of a connected session.

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error.

Wrapper around [`lib.ssh_get_server_publickey()`](@ref).
"""
function get_server_publickey(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot get the servers public key"))
    end

    key_ref = Ref{lib.ssh_key}()
    ret = lib.ssh_get_server_publickey(session, key_ref)
    if ret != SSH_OK
        throw(LibSSHException("Error when getting servers public key: $(ret)"))
    end

    return PKI.SshKey(key_ref[])
end

"""
$(TYPEDSIGNATURES)

Check if the connected servers public key exists in the SSH known hosts
file.

# Throws
- `ArgumentError`: If the session isn't connected.
- [`HostVerificationException`](@ref): If verification failed and
  `throw` is `true`.

# Arguments
- `throw=true`: Whether to throw a
  [`HostVerificationException`](@ref) if the verification fails, otherwise the
  function will just return the verification status.

Wrapper around [`lib.ssh_session_is_known_server()`](@ref).
"""
function is_known_server(session::Session; throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot check the servers public key"))
    end

    status = KnownHosts(Int(lib.ssh_session_is_known_server(session)))
    if throw && status != KnownHosts_Ok
        Base.throw(HostVerificationException(status))
    end

    return status
end

"""
$(TYPEDSIGNATURES)

Update the users known hosts file with the sessions server key.

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error.

Wrapper around [`lib.ssh_session_update_known_hosts()`](@ref).
"""
function update_known_hosts(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot get the servers public key to update the known hosts file"))
    end

    ret = lib.ssh_session_update_known_hosts(session)
    if ret != SSH_OK
        throw(LibSSHException("Could not update the users known hosts file: $(ret)"))
    end
end

# Helper function to call userauth_kbdint() until we get a non-AuthStatus_Info
# response.
function _try_userauth_kbdint(session::Session, answers, throw)
    # We keep track of when we need to start an keyboard-interactive auth
    # session with the server through the _require_init_kbdint field.
    if session._require_init_kbdint
        userauth_kbdint(session; throw)
    end

    if !isnothing(answers)
        userauth_kbdint_setanswers(session, answers)
    end

    status = userauth_kbdint(session; throw)
    if status == AuthStatus_Info
        prompts = userauth_kbdint_getprompts(session)

        # If the server responds with Info but doesn't send any prompts, then we
        # just keep trying until we get something different. Servers can do that.
        if isempty(prompts)
            return _try_userauth_kbdint(session, nothing, throw)
        end
    end

    # If the auth session is 'over', then set the _require_init_kbdint field so
    # that we know to call userauth_kbdint() again the next time it's tried.
    if status == AuthStatus_Denied
        session._require_init_kbdint = true
    end

    return status
end

function _can_attempt_auth(session::Session, auth_method::AuthMethod)
    auth_method in session._auth_methods && auth_method ∉ session._attempted_auth_methods
end

"""
$(TYPEDSIGNATURES)

This is a helper function that boldly attempts to handle the entire
authentication flow by figuring out which authentication methods are still
available and calling the appropriate functions for you. It may need to be
called multiple times to complete authentication, the idea is that it will only
return when user input is needed (e.g. for a password, or to accept a host key,
etc).

It can return any of:
- A [`KnownHosts`](@ref) to indicate that host verification failed in some
  way. It will not return `KnownHosts_Ok`.
- A [`AuthStatus`](@ref) to indicate that authentication finished in some
  way. The caller doesn't need to do anything else in this case but may retry
  authenticating. It will not return
  `AuthStatus_Info`/`AuthStatus_Again`/`AuthStatus_Partial`.
- A [`AuthMethod`](@ref) to indicate the next method to try. This is only
  returned for auth methods that require user input (i.e. `AuthMethod_Password`
  or `AuthMethod_Interactive`), and the caller must pass the user input next
  time they call `authenticate()`.

!!! warning
    If you're using this function do *not* call any of the other `userauth_*`
    functions, except for [`userauth_kbdint_getprompts()`](@ref) to get the
    server prompts if necessary. `authenticate()` maintains some internal state
    to keep track of where it is in authentication, which can be messed up by
    calling other auth methods yourself.

!!! warning
    `authenticate()` is quite experimental, we suggest testing it with
    [`authenticate_cli()`](@ref) to verify it works on the servers you're
    authenticating to.

# Arguments
- `session`: The [`Session`](@ref) to authenticate.
- `password=nothing`: A password to authenticate with. Pass this if
  `authenticate()` previously returned `AuthMethod_Password`.
- `kbdint_answers=nothing`: Answers to keyboard-interactive prompts from the
  server. Use [`userauth_kbdint_getprompts()`](@ref) to get the prompts if
  `authenticate()` returns `AuthMethod_Interactive` and then pass the answers in
  the next call.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected, or if both `password` and
  `kbdint_answers` are passed.
- `ErrorException`: If there are no more supported authentication methods
  available.
- `LibSSHException`: If there's an internal error and `throw=true`.
"""
function authenticate(session::Session; password=nothing, kbdint_answers=nothing,
                      throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot authenticate"))
    elseif !isnothing(password) && !isnothing(kbdint_answers)
        Base.throw(ArgumentError("Only one of `password` or `kbdint_answers` may be passed"))
    end

    # Verify the host key
    host_status = is_known_server(session; throw=false)
    if host_status == KnownHosts_Error
        Base.throw("Error while verifying host key for '$(session.host)': $(host_status)")
    elseif host_status != KnownHosts_Ok
        return host_status
    end

    # Retrieve the supported methods
    session._auth_methods = userauth_list(session;
                                          call_auth_none=isnothing(session._auth_methods))

    # First we check if any of the input arguments have been passed, and we
    # attempt authentication if so.
    if !isnothing(password) || !isnothing(kbdint_answers)
        status = if !isnothing(password)
            userauth_password(session, password; throw)
        else
            _try_userauth_kbdint(session, kbdint_answers, throw)
        end

        # For the sake of consistency we never return AuthStatus_Info to the
        # caller.
        if !isnothing(kbdint_answers) && status == AuthStatus_Info
            status = AuthMethod_Interactive
        end

        return status == AuthStatus_Partial ? authenticate(session; throw) : status
    end

    if isempty(session._auth_methods)
        error("Could not authenticate to the server, no authenication methods left")
    end

    # Otherwise we go through the support auth methods and select one to try.

    # First we try GSSAPI. Handling this one is a little complex because it's
    # allowed to fail if the user hasn't got a ticket for the server.
    if (_can_attempt_auth(session, AuthMethod_GSSAPI_MIC)
        && Gssapi.isavailable()
        && !isnothing(Gssapi.principal_name()))
        status = userauth_gssapi(session; throw)

        if status == AuthStatus_Denied
            push!(session._attempted_auth_methods, AuthMethod_GSSAPI_MIC)

            # If the ticket isn't valid but there are still other methods
            # available, continue trying. Otherwise just return Denied.
            if length(session._auth_methods) > 1
                return authenticate(session; throw)
            else
                return status
            end
        elseif status == AuthStatus_Partial
            # If we're now partially authenticated, then we continue with some
            # other method.
            return authenticate(session; throw)
        else
            return status
        end
    end

    # Then password auth
    if _can_attempt_auth(session, AuthMethod_Password)
        return AuthMethod_Password
    end

    # Then keyboard-interactive auth
    if _can_attempt_auth(session, AuthMethod_Interactive)
        # Start a keyboard-interactive session if necessary. We call this now so
        # that the caller can call userauth_kbdint_getprompts() immediately.
        if session._require_init_kbdint
            userauth_kbdint(session; throw)
        end

        return AuthMethod_Interactive
    end

    error("The remaining auth methods are not supported: $(session._auth_methods)")
end

function _ask(msg::String)
    print(msg, " [y/n]: ")
    ret = readline()
    return lowercase(ret) == "y"
end

"""
$(TYPEDSIGNATURES)

Meant to mimic authenticating with the `ssh` command by calling
[`authenticate()`](@ref) in a loop while prompting the user if necessary. It's
useful to use this at the REPL to test whether the server can be authenticated
to at all.

# Examples
```julia-repl
julia> session = ssh.Session("test.com"; user="myuser")
LibSSH.Session(host=test.com, port=22, user=myuser, connected=true)

julia> ssh.authenticate_cli(session)
Password:
[ Info: AuthStatus_Info
One-time password:
[ Info: AuthStatus_Success
AuthStatus_Success::AuthStatus = 0
```
"""
function authenticate_cli(session::Session)
    ret = nothing

    while ret != AuthStatus_Success
        ret = authenticate(session)

        if ret == AuthMethod_Password
            buf = Base.getpass("Password")
            println()
            password = read(buf, String)
            Base.shred!(buf)

            ret = authenticate(session; password)
        elseif ret == AuthMethod_Interactive
            prompts = userauth_kbdint_getprompts(session)
            answers = String[]
            for prompt in prompts
                # TODO: use `with_suffix` in Julia 1.12. See
                # https://github.com/JuliaLang/julia/pull/53614.
                buf = Base.getpass(chopsuffix(prompt.msg, ": "))
                println()
                push!(answers, read(buf, String))
                Base.shred!(buf)
            end

            ret = authenticate(session; kbdint_answers=answers)
        elseif ret isa KnownHosts
            server_key = get_server_publickey(session)
            fingerprint = PKI.get_fingerprint_hash(server_key)
            key_type = PKI.key_type(server_key)

            notfound_msg = ret == KnownHosts_NotFound ? " This will create the known_hosts file." : ""
            first_line = if ret == KnownHosts_Changed
                "The server key has changed ($(ret)), this may indicate a MITM attack."
            elseif ret == KnownHosts_Other
                "The server key has changed type ($(ret)) to $(key_type), this may indicate a MITM attack."
            elseif ret == KnownHosts_Unknown || ret == KnownHosts_NotFound
                "Server '$(session.host)' has not been seen before ($(ret))."
            end

            println(first_line)
            println("New $(key_type) key fingerprint: $(fingerprint)")
            if _ask("Do you want to add the key to the known_hosts file and continue?$(notfound_msg)")
                update_known_hosts(session)
            else
                # We can't continue if they don't accept the key
                return ret
            end
        elseif ret == AuthStatus_Success
            # Do nothing
        else
            error("Unsupported return value from authenticate(): $(ret)")
        end

        @info ret
    end

    return ret
end

"""
$(TYPEDSIGNATURES)

Attempt to authenticate to the server without any credentials. This
authentication method is always disabled in practice, but it's still useful to
check which authentication methods the server supports (see
[`userauth_list()`](@ref)).

# Arguments
- `session`: The session to authenticate.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error, unless `throw=false`.

Wrapper around [`lib.ssh_userauth_none()`](@ref).
"""
function userauth_none(session::Session; throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    while true
        ret = AuthStatus(lib.ssh_userauth_none(session, C_NULL))

        if ret == AuthStatus_Again
            wait(session)
        elseif ret == AuthStatus_Error && throw
            Base.throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when calling userauth_none()"))
        else
            return ret
        end
    end
end

"""
$(TYPEDSIGNATURES)

Get a list of support authentication methods from the server. This will
automatically call [`userauth_none()`](@ref) beforehand if `call_auth_none=true`
(the default).

# Throws
- `ArgumentError`: If the session isn't connected.

Wrapper around [`lib.ssh_userauth_list()`](@ref).
"""
function userauth_list(session::Session; call_auth_none=true)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    # First we have to call ssh_userauth_none() for... some reason, according to
    # the docs.
    if call_auth_none
        userauth_none(session)
    end

    ret = lib.ssh_userauth_list(session, C_NULL)
    auth_methods = AuthMethod[]
    for method in instances(AuthMethod)
        if (Int(method) & ret) > 0
            push!(auth_methods, method)
        end
    end

    return auth_methods
end

"""
$(TYPEDSIGNATURES)

Authenticate by username and password. The username will be taken from
`session.user`.

# Arguments
- `session`: The session to authenticate.
- `password`: The password to authenticate with.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error, unless `throw=false`.

Wrapper around [`lib.ssh_userauth_password()`](@ref).
"""
function userauth_password(session::Session, password::String; throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    while true
        GC.@preserve password begin
            password_cstr = Base.unsafe_convert(Ptr{Cchar}, password)
            ret = AuthStatus(lib.ssh_userauth_password(session, C_NULL, password_cstr))
        end

        if ret == AuthStatus_Again
            wait(session)
        elseif ret == AuthStatus_Error && throw
            Base.throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when authenticating"))
        else
            return ret
        end
    end
end

"""
$(TYPEDSIGNATURES)

Authenticate with GSSAPI. This is not available on all platforms (see
[`Gssapi.isavailable()`](@ref)).

# Arguments
- `session`: The session to authenticate.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `ErrorException`: If GSSAPI support isn't available.
- `LibSSHException`: If there was an internal error, unless `throw=false`.

Wrapper around [`lib.ssh_userauth_gssapi()`](@ref).
"""
function userauth_gssapi(session::Session; throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    elseif !Gssapi.isavailable()
        error("GSSAPI support is not available")
    end

    ret = _session_trywait(session) do
        lib.ssh_userauth_gssapi(session)
    end
    status = AuthStatus(ret)

    if status == AuthStatus_Error && throw
        Base.throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when authenticating"))
    end

    return status
end

"""
$(TYPEDSIGNATURES)

Attempt to authenticate with the keyboard-interactive method.

# Arguments
- `session`: The session to authenticate.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error, unless `throw=false`.

Wrapper around [`lib.ssh_userauth_kbdint`](@ref).
"""
function userauth_kbdint(session::Session; throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    ret = _session_trywait(session) do
        lib.ssh_userauth_kbdint(session, C_NULL, C_NULL)
    end
    status = AuthStatus(ret)

    if status == AuthStatus_Error && throw
        Base.throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when authenticating"))
    end

    session._require_init_kbdint = false

    return status
end

"""
$(TYPEDSIGNATURES)

Returns all the keyboard-interactive prompts from the server. You should have
already called [`userauth_kbdint()`](@ref). The `KbdintPrompt` objects it
returns have `.msg` and `.display` fields that hold the prompt message and
whether to echo the user input (e.g. it will be `false` for a password and other
sensitive input).

This is a combination of [`lib.ssh_userauth_kbdint_getnprompts()`](@ref) and
[`lib.ssh_userauth_kbdint_getprompt()`](@ref). It should be preferred over the
lower-level functions.

# Throws
- `ArgumentError`: If the session isn't connected.
"""
function userauth_kbdint_getprompts(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    prompts = KbdintPrompt[]
    n_prompts = lib.ssh_userauth_kbdint_getnprompts(session)
    for i in 0:n_prompts - 1
        echo_ref = Ref{Cchar}()
        question = lib.ssh_userauth_kbdint_getprompt(session, i, echo_ref)
        push!(prompts, KbdintPrompt(question, Bool(echo_ref[])))
    end

    return prompts
end

"""
$(TYPEDSIGNATURES)

Sets answers for a keyboard-interactive auth session. Uses
[`lib.ssh_userauth_kbdint_setanswer`](@ref) internally.

# Arguments
- `session`: The session to authenticate.
- `answers`: A vector of answers for each prompt sent by the server.

# Throws
- `ArgumentError`: If the session isn't connected, or if the wrong number of
  answers were passed.
- `LibSSHException`: If setting the answers failed.
"""
function userauth_kbdint_setanswers(session::Session, answers::Vector{String})
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    n_prompts = lib.ssh_userauth_kbdint_getnprompts(session)
    if n_prompts != length(answers)
        throw(ArgumentError("Server sent $(n_prompts) prompts, but was passed $(length(answers)) answers"))
    end

    for (i, answer) in enumerate(answers)
        ret = lib.ssh_userauth_kbdint_setanswer(session, i - 1,
                                                Base.cconvert(Cstring, answer))
        if ret != SSH_OK
            throw(LibSSHException("Error while setting answer $(i) with ssh_userauth_kbdint_setanswer(): $(ret)"))
        end
    end
end

#=
Helper function to aid with calling non-blocking functions. It will try calling
`f()` as long as `f()` returns `SSH_AGAIN` or `SSH_AUTH_AGAIN`.
=#
function _session_trywait(f::Function, session::Session)
    ret = SSH_ERROR

    while true
        ret = @lock session f()

        if ret != SSH_AGAIN && ret != lib.SSH_AUTH_AGAIN
            break
        else
            try
                wait(session)
            catch ex
                if ex isa Base.IOError
                    # An IOError will sometimes (!) occur if the socket was
                    # closed in the middle of waiting.
                    break
                else
                    rethrow()
                end
            end
        end
    end

    return ret
end
