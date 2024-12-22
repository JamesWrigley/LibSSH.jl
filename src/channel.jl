import Dates

import Sockets
import Sockets: TCPServer, TCPSocket, IPv4, getaddrinfo

"""
$(TYPEDEF)
$(TYPEDFIELDS)

Wraps a `lib.ssh_channel`. An `SshChannel` can be owning or non-owning
of a pointer to the underlying `lib.ssh_channel`, and only owning `SshChannel`s
can be closed with [`close(::SshChannel)`](@ref).

The type is named `SshChannel` to avoid confusion with Julia's own `Channel`
type.

!!! warning
    If callbacks are set on an `SshChannel` (e.g. to implement a server) it
    *must* be closed explicitly with [`Base.close(::SshChannel)`](@ref). It is
    not safe to allow the finalizer to clean up the resources since callback
    functions may be called while the `SshChannel` is closed and they may yield
    to allow task switching, which is forbidden inside finalizers.
"""
mutable struct SshChannel
    ptr::Union{lib.ssh_channel, Nothing}
    owning::Bool
    session::Union{Session, Nothing}
    close_lock::ReentrantLock
    local_eof::Bool
    callbacks::Union{Callbacks.ChannelCallbacks, Nothing}

    @doc """
    $(TYPEDSIGNATURES)

    Wrap a `SshChannel` around an already existing `lib.ssh_channel`. Don't use
    this unless you know what you're doing, prefer the
    [`SshChannel(::Session)`](@ref) constructor instead.
    """
    function SshChannel(ptr::lib.ssh_channel, session=nothing; own=true)
        if own && isnothing(session)
            throw(ArgumentError("You must pass a session to an owning SshChannel"))
        elseif !own && !isnothing(session)
            throw(ArgumentError("Only owning SshChannels can be associated with a Session"))
        elseif own && !isnothing(session) && !session.owning
            throw(ArgumentError("Cannot create a SshChannel from a non-owning Session"))
        end
        self = new(ptr, own, session, ReentrantLock(), false, nothing)

        if own
            push!(session.closeables, self)
            finalizer(_finalizer, self)
        end

        return self
    end
end

# close(SshChannel) can throw, which we don't want to happen in a finalizer so
# we wrap it in a try-catch.
function _finalizer(sshchan::SshChannel)
    if trylock(sshchan.close_lock)
        try
            close(sshchan)
        catch ex
            # Note the use of @spawn to avoid a task switch, which is forbidden in a
            # finalizer.
            Threads.@spawn @error "Caught exception while finalizing SshChannel" exception=(ex, catch_backtrace())
        finally
            unlock(sshchan.close_lock)
        end
    else
        finalizer(_finalizer, sshchan)
    end
end

"""
$(TYPEDSIGNATURES)

Create a channel from an existing session. Note that creating the channel will
fail unless the session is connected *and* authenticated.
"""
function SshChannel(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Cannot create a SshChannel on an unconnected Session"))
    end

    ptr = lib.ssh_channel_new(session)
    if ptr == C_NULL
        throw(LibSSHException("Could not allocate ssh_channel (hint: check that the session is authenticated)"))
    end

    return SshChannel(ptr, session)
end

"""
$(TYPEDSIGNATURES)

Do-constructor for a `SshChannel`. This will ensure that the channel is closed
after `f()` completes.

Example:
```julia
data = ssh.SshChannel(session) do sshchan
    return 42
end
@assert data == 42
```
"""
function SshChannel(f::Function, session::Session)
    sshchan = SshChannel(session)

    try
        return f(sshchan)
    finally
        close(sshchan)
    end
end

function Base.unsafe_convert(::Type{lib.ssh_channel}, sshchan::SshChannel)
    if !isassigned(sshchan)
        throw(ArgumentError("SshChannel is unassigned, cannot get a pointer from it"))
    end

    return sshchan.ptr
end

function Base.show(io::IO, sshchan::SshChannel)
    print(io, SshChannel, "(ptr=$(sshchan.ptr), owning=$(sshchan.owning))")
end

"""
$(TYPEDSIGNATURES)

Check if the channel holds a valid pointer to a `lib.ssh_channel`.
"""
Base.isassigned(sshchan::SshChannel) = !isnothing(sshchan.ptr)

Base.lock(sshchan::SshChannel) = lock(sshchan.session)
Base.unlock(sshchan::SshChannel) = unlock(sshchan.session)

"""
$(TYPEDSIGNATURES)

Checks if the channel is open. Wrapper around
[`lib.ssh_channel_is_open()`](@ref).
"""
function Base.isopen(sshchan::SshChannel)
    if isassigned(sshchan) && (isnothing(sshchan.session) || isconnected(sshchan.session))
        lib.ssh_channel_is_open(sshchan) != 0
    else
        false
    end
end

"""
$(TYPEDSIGNATURES)

Closes the channel, and then frees its memory. To avoid the risk of
double-frees, this function may only be called on *owning* `SshChannel`s. It
will hold the `close_lock` of the channel during execution.

# Arguments
- `sshchan`: The [`SshChannel`](@ref) to close.
- `allow_fail=false`: Whether to throw an exception if the call to
  [`lib.ssh_channel_close()`](@ref) fails. In some cases it can fail for valid
  reasons, such as the socket already having been closed by the other end (this
  will result in a `Socket error: disconnected` error).
"""
function Base.close(sshchan::SshChannel; allow_fail=false)
    # Developer note: this function is called by the SshChannel finalizer, which
    # means we aren't allowed to do task switches.

    if !sshchan.owning
        throw(ArgumentError("Calling close() on a non-owning SshChannel is not allowed to avoid accidental double-frees, see the docs for more information."))
    end

    session = sshchan.session

    # Note that the finalizer will take the lock before calling close(), so
    # we can safely call @lock here.
    @lock sshchan.close_lock begin
        # Even though we hold a lock in this section it's still possible for the
        # function to be called recursively and enter it again anyway. The reason is
        # because lib.ssh_channel_send_eof() and lib.ssh_channel_close() both flush
        # the channel, which will trigger any callbacks. And if the callbacks happen
        # to call close(), then the lock will be taken anyway (because it's a
        # reentrant lock). There's not much we can do about this apart from making
        # close() as robust as possible, which is why there are so many checks.

        if isassigned(sshchan)
            # Remove from the sessions list of active channels. findfirst()
            # should only return nothing if the function is being called
            # recursively (i.e. through a callback) and it was already removed.
            @lock session begin
                idx = findfirst(x -> x === sshchan, session.closeables)
                if !isnothing(idx)
                    popat!(session.closeables, idx)
                end
            end

            if !isnothing(sshchan.session) && (@lock session !isconnected(session))
                # If the session has already been disconnected from C
                # (e.g. because of the other side disconnecting) then that will
                # already have free'd the channel, which means we only need to
                # unassign the pointer.
                sshchan.ptr = nothing
            elseif isopen(sshchan)
                # This will trigger callbacks
                closewrite(sshchan; allow_fail)

                if isopen(sshchan)
                    # This will trigger callbacks
                    ret = lib.ssh_channel_close(sshchan)
                    if ret != SSH_OK
                        msg = "Closing SshChannel failed with $(ret): '$(get_error(session))'"
                        if allow_fail
                            # Note that we spawn to avoid task switches
                            Threads.@spawn @warn msg
                        else
                            throw(LibSSHException(msg))
                        end
                    end
                end
            end

            # Free the memory
            if isassigned(sshchan)
                lib.ssh_channel_free(sshchan)
                sshchan.ptr = nothing
            end
        end
    end
end

"""
$(TYPEDSIGNATURES)

Write a string to the channel and return the number of code units written.

Wrapper around
[`lib.ssh_channel_write()`](@ref)/[`lib.ssh_channel_write_stderr()`](@ref).
"""
function Base.write(sshchan::SshChannel, data::AbstractString; stderr::Bool=false)
    array = Vector{UInt8}(data)
    return write(sshchan, array; stderr)
end

"""
$(TYPEDSIGNATURES)

Write a byte array to the channel and return the number of bytes written (should
always match the length of the array, unless there was an error, in which case
this will throw an exception).

Wrapper around
[`lib.ssh_channel_write()`](@ref)/[`lib.ssh_channel_write_stderr()`](@ref).
"""
function Base.write(sshchan::SshChannel, data::Vector{UInt8}; stderr::Bool=false)
    ret = SSH_ERROR

    @lock sshchan begin
        if !isassigned(sshchan) || !isopen(sshchan)
            throw(ArgumentError("SshChannel has been closed, is not writeable"))
        end

        writer = stderr ? lib.ssh_channel_write_stderr : lib.ssh_channel_write

        GC.@preserve data begin
            ptr = Ptr{Cvoid}(pointer(data))
            ret = writer(sshchan, ptr, length(data))
        end
    end

    if ret == SSH_ERROR
        throw(LibSSHException("Error when writing to channel: $(ret)"))
    end

    return Int(ret)
end

"""
$(TYPEDSIGNATURES)

Check if an EOF has been sent *by the remote end*. This does *not* imply that an
EOF has been sent from the local end and thus the channel is not writable (for
that, use [`iswritable(::SshChannel)`](@ref)). Check `SshChannel.local_eof` to
check if an EOF has been sent from the local end.

Wrapper around [`lib.ssh_channel_is_eof()`](@ref).
"""
function Base.eof(sshchan::SshChannel)
    if isassigned(sshchan)
        lib.ssh_channel_is_eof(sshchan) != 0
    else
        true
    end
end

"""
$(TYPEDSIGNATURES)

Check if the channel is writable.
"""
function Base.iswritable(sshchan::SshChannel)
    if isassigned(sshchan) && isopen(sshchan)
        !sshchan.local_eof
    else
        false
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around [`lib.ssh_set_channel_callbacks()`](@ref) and
[`lib.ssh_remove_channel_callbacks()`](@ref). Unlike
[`lib.ssh_set_channel_callbacks()`](@ref) this will replace any existing
callbacks.

# Throws
- [`LibSSHException`](@ref): If setting the callbacks failed.
"""
function set_channel_callbacks(sshchan::SshChannel, callbacks::Callbacks.ChannelCallbacks)
    if !isnothing(sshchan.callbacks)
        remove_channel_callbacks(sshchan, sshchan.callbacks)
    end

    ret = lib.ssh_set_channel_callbacks(sshchan, Ref(callbacks.cb_struct))
    if ret != SSH_OK
        throw(LibSSHException("Error when setting channel callbacks: $(ret)"))
    end
    sshchan.callbacks = callbacks
end

# Undocumented for now because the API for setting callbacks isn't fleshed out yet
function remove_channel_callbacks(sshchan::SshChannel, callbacks::Callbacks.ChannelCallbacks)
    ret = lib.ssh_remove_channel_callbacks(sshchan, Ref(callbacks.cb_struct))
    if ret != SSH_OK
        throw(LibSSHException("Error when removing channel callbacks: $(ret)"))
    end
    sshchan.callbacks = nothing
end

"""
$(TYPEDSIGNATURES)

Sends an EOF message. Calling this function will trigger any waiting callbacks.

# Throws
- `ArgumentError`: if the channel is not writable.

Wrapper around [`lib.ssh_channel_send_eof()`](@ref).

# Arguments
- `sshchan`: The [`SshChannel`](@ref) to send an EOF on.
- `allow_fail=false`: Whether to throw an exception if the call to
  [`lib.ssh_channel_send_eof()`](@ref) fails. In some cases it can fail for
  valid reasons, such as the socket already having been closed by the other end
  (this will result in a `Socket error: disconnected` error).
"""
function Base.closewrite(sshchan::SshChannel; allow_fail=false)
    @lock sshchan begin
        # If we've already sent an EOF, do nothing
        if sshchan.local_eof
            return
        end

        if !iswritable(sshchan)
            throw(ArgumentError("SshChannel has been closed, cannot send EOF"))
        end

        ret = lib.ssh_channel_send_eof(sshchan)
        if ret != SSH_OK
            error_msg = get_error(sshchan.session)
            if allow_fail
                Threads.@spawn @warn "closewrite() on SshChannel failed: '$(error_msg)'"
            else
                throw(LibSSHException("Error when sending EOF on channel: '$(error_msg)'"))
            end
        end

        sshchan.local_eof = true
    end
end

@deprecate channel_send_eof(sshchan::SshChannel) closewrite(sshchan)

"""
$(TYPEDSIGNATURES)

Sends an exit status in reponse to an exec request. Wrapper around
[`lib.ssh_channel_request_send_exit_status()`](@ref).
"""
function channel_request_send_exit_status(sshchan::SshChannel, status::Integer)
    ret = @lock sshchan begin
        if !isopen(sshchan)
            throw(ArgumentError("SshChannel has been closed, cannot send exit status"))
        end

        lib.ssh_channel_request_send_exit_status(sshchan, Cint(status))
    end

    if ret != SSH_OK
        throw(LibSSHException("Error when sending exit status on channel: $(ret)"))
    end
end

"""
$(TYPEDSIGNATURES)

Poll a (owning) channel in a loop while it's alive, which will trigger any
callbacks. This function should always be called on a channel for it to work
properly. It will return:
- `nothing` if the channel was closed during the loop.
- Otherwise the last result from [`lib.ssh_channel_poll()`](@ref), which should
  be checked to see if it's `SSH_EOF`.

# Throws
- [`LibSSHException`](@ref): If `SSH_ERROR` is returned and
  `throw=true`.

# Arguments
- `sshchan`: The [`SshChannel`](@ref) to poll.
- `throw=true`: Whether to throw an exception if `SSH_ERROR` is
  returned.
"""
function poll_loop(sshchan::SshChannel; throw=true)
    if !sshchan.owning
        Base.throw(ArgumentError("Polling is only possible for owning SshChannel's, the passed channel is non-owning"))
    end

    ret = SSH_ERROR
    while true
        # Poll stdout and stderr
        for io_stream in (0, 1)
            # We always check if the channel and session are open within the loop
            # because ssh_channel_poll() will execute callbacks, which could close
            # them before returning.
            if !isopen(sshchan)
                return nothing
            end

            # Note that we don't actually read any data in this loop, that's
            # handled by the callbacks, which are called by ssh_channel_poll().
            ret = @lock sshchan lib.ssh_channel_poll(sshchan, io_stream)

            # Break if there was an error, or if an EOF has been sent. We use a
            # @goto here (Knuth forgive me) to break out of the outer loop as
            # well as the inner one.
            if ret == SSH_ERROR || ret == SSH_EOF
                @goto loop_end
            end
        end

        if !isopen(sshchan.session)
            return nothing
        end

        wait(sshchan.session)
    end

    @label loop_end

    if ret == SSH_ERROR && throw
        Base.throw(LibSSHException("SSH_ERROR returned from lib.ssh_channel_poll()"))
    end

    return Int(ret)
end

## execute()

function _log(msg, process)
    if process._verbose
        @info "execute(): $(msg)"
    end
end

function _on_channel_data(session, sshchan, data, is_stderr, process)
    is_stderr = Bool(is_stderr)
    fd_msg = is_stderr ? "stderr" : "stdout"
    _log("channel_data $(length(data)) bytes from $fd_msg", process)

    append!(is_stderr ? process.err : process.out, data)

    return length(data)
end

function _on_channel_eof(session, sshchan, process)
    _log("channel_eof", process)
end

function _on_channel_close(session, sshchan, process)
    _log("channel_close", process)
end

function _on_channel_exit_status(session, sshchan, ret, process)
    _log("exit_status $ret", process)
    process.exitcode = Int(ret)
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

This is analogous to `Base.Process`, it represents a command running over an
SSH session. The stdout and stderr output are stored as byte arrays in
`SshProcess.out` and `SshProcess.err` respectively. They can be converted to
strings using e.g. `String(copy(process.out))`.
"""
@kwdef mutable struct SshProcess
    out::Vector{UInt8} = Vector{UInt8}()
    err::Vector{UInt8} = Vector{UInt8}()

    cmd::Union{Cmd, String, Nothing} = nothing
    exitcode::Int = typemin(Int)

    _sshchan::Union{SshChannel, Nothing} = nothing
    _task::Union{Task, Nothing} = nothing
    _verbose::Bool = false
end

function Base.show(io::IO, process::SshProcess)
    status = process_running(process) ? "ProcessRunning" : "ProcessExited($(process.exitcode))"
    print(io, SshProcess, "(cmd=$(process.cmd), $status)")
end

Base.process_running(process::SshProcess) = !istaskdone(process._task)
Base.process_exited(process::SshProcess) = istaskdone(process._task)

"""
$(TYPEDSIGNATURES)

Check if the process succeeded.
"""
Base.success(process::SshProcess) = process_exited(process) && process.exitcode == 0

"""
$(TYPEDSIGNATURES)

# Throws
- [`SshProcessFailedException`](@ref): if `ignorestatus()` wasn't used.
"""
function Base.wait(process::SshProcess)
    try
        wait(process._task)
    catch task_ex
        ex = process._task.exception

        # The idea is that SshProcessFailedException's and LibSSHException's are
        # somewhat expected so we always unwrap them from the
        # TaskFailedException before throwing, which is a slightly nicer API to
        # work with.
        if ex isa SshProcessFailedException || ex isa LibSSHException
            if !(process.cmd isa Cmd && process.cmd.ignorestatus)
                throw(process._task.exception)
            end
        else
            rethrow()
        end
    end
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

This is analogous to `ProcessFailedException`.
"""
struct SshProcessFailedException <: Exception
    process::SshProcess
end

function _exec_command(process::SshProcess)
    sshchan = process._sshchan
    session = sshchan.session
    is_cmd = process.cmd isa Cmd
    cmd_str = is_cmd ? Base.shell_escape(process.cmd) : process.cmd

    # Open the session channel
    ret = _session_trywait(session) do
        lib.ssh_channel_open_session(sshchan)
    end
    if ret != SSH_OK
        throw(LibSSHException("Failed to open a session channel: $(ret)"))
    end

    # Set environment variables
    if is_cmd && !isnothing(process.cmd.env)
        for env_var in process.cmd.env
            # We explicitly convert the SubString's returned from split() to
            # String's so that they're each separate and null-terminated in
            # memory, otherwise the entire 'name=value' string would be sent
            # when we send `name`.
            name, value = String.(split(env_var, "="))
            ret = _session_trywait(session) do
                lib.ssh_channel_request_env(sshchan, name, value)
            end

            if ret != SSH_OK
                err = get_error(session)
                throw(LibSSHException("Error from lib.ssh_channel_request_env(), could not set environment variable '$(env_var)': '$(err)'. Hint: check that the server has an `AcceptEnv` config that allows setting this variable, otherwise it will fail."))
            end
        end
    end

    # Make the request
    ret = _session_trywait(session) do
        GC.@preserve cmd_str begin
            lib.ssh_channel_request_exec(sshchan, Base.unsafe_convert(Ptr{Cchar}, cmd_str))
        end
    end
    if ret != SSH_OK
        err = get_error(session)
        throw(LibSSHException("Error from lib.ssh_channel_request_exec, could not execute command: $(err)"))
    end

    # Wait for data to be read
    ret = poll_loop(sshchan)

    # Close the channel
    if iswritable(sshchan)
        closewrite(sshchan)
    end
    close(sshchan)

    # Check the result of the read for an error
    if ret == SSH_ERROR
        throw(LibSSHException("Error while reading data from channel: $(ret)"))
    end

    if (!is_cmd || !process.cmd.ignorestatus) && process.exitcode != 0
        throw(SshProcessFailedException(process))
    end
end

"""
$(TYPEDSIGNATURES)

Run a command on the remote host over an SSH session. Things that aren't
supported compared to `run()`:
- Pipelined commands (use a regular pipe like `foo | bar` instead).
- Setting the directory to execute the command in.

An easy way of getting around these restrictions is to pass the command as a
`String` instead of `Cmd`.

!!! note
    Setting environment variables is supported, but will fail if the server
    forbids setting them.

# Throws
- [`SshProcessFailedException`](@ref): if the command fails and `ignorestatus()`
  wasn't used.
- [`LibSSHException`](@ref): if running the command fails for some other
  reason.

# Arguments
- `cmd`: The command to run. This will be converted to a string for running
  remotely.
- `session`: The session to run the command over.
- `wait=true`: Wait for the command to finish before returning.
- `verbose=false`: Print debug logging messages. Note that this is not the same
  as setting the `log_verbosity` on a [`Session`](@ref).
- `combine_outputs=true`: Write the `stderr` command output to the `IOBuffer`
  for the commands `stdout`. If this is `true` then `SshProcess.out` and
  `SshProcess.err` will refer to the same object.
- `print_out=true`: Print the output (stdout + stderr by default) of the
  command.

# Examples
```julia-repl
julia> import LibSSH as ssh

julia> ssh.Demo.DemoServer(2222; password="foo") do
           session = ssh.Session("127.0.0.1", 2222)
           @assert ssh.userauth_password(session, "foo") == ssh.AuthStatus_Success

           @info "1"
           run(`echo foo`, session)

           println()
           @info "2"
           run(ignorestatus(`foo`), session)

           println()
           @info "3"
           # Pass a string to avoid hacking around Cmd syntax
           run("cd /tmp && pwd", session)
       end
[ Info: 1
foo

[ Info: 2
sh: line 1: foo: command not found

[ Info: 3
/tmp
```
"""
function Base.run(cmd::Union{Cmd, String}, session::Session;
                  wait::Bool=true, verbose::Bool=false,
                  combine_outputs::Bool=true, print_out::Bool=true)
    process = SshProcess(; cmd, _verbose=verbose)
    if combine_outputs
        process.err = process.out
    end

    callbacks = Callbacks.ChannelCallbacks(process;
                                           on_eof=_on_channel_eof,
                                           on_close=_on_channel_close,
                                           on_data=_on_channel_data,
                                           on_exit_status=_on_channel_exit_status)
    process._sshchan = SshChannel(session)
    set_channel_callbacks(process._sshchan, callbacks)

    process._task = Threads.@spawn _exec_command(process)

    if wait
        # Note the use of Base.wait() to avoid aliasing with the `wait` argument
        Base.wait(process)

        if print_out
            print(String(copy(process.out)))
        end
    end

    return process
end

"""
$(TYPEDSIGNATURES)

Read the output from the command in bytes.
"""
function Base.read(cmd::Union{Cmd, String}, session::Session)
    process = run(cmd, session; print_out=false)
    return process.out
end

"""
$(TYPEDSIGNATURES)

Read the output from the command as a String.

# Examples
```julia-repl
julia> import LibSSH as ssh

julia> ssh.Demo.DemoServer(2222; password="foo") do
           session = ssh.Session("127.0.0.1", 2222)
           @assert ssh.userauth_password(session, "foo") == ssh.AuthStatus_Success

           @show read(`echo foo`, session, String)
       end
read(`echo foo`, session, String) = "foo\\n"
```
"""
Base.read(cmd::Union{Cmd, String}, session::Session, ::Type{String}) = String(read(cmd, session))

"""
$(TYPEDSIGNATURES)

`readchomp()` for remote commands.
"""
Base.readchomp(cmd::Union{Cmd, String}, session::Session) = chomp(read(cmd, session, String))

"""
$(TYPEDSIGNATURES)

Check the command succeeded.
"""
Base.success(cmd::Union{Cmd, String}, session::Session) = success(run(cmd, session; print_out=false))

## Direct port forwarding

# Handler for receiving data from the server
function _on_client_channel_data(session, sshchan, data, is_stderr, client)
    _logcb(client, "Received $(length(data)) bytes from server")

    if isopen(client.sock)
        write(client.sock, data)
    else
        @warn "Client socket has been closed, dropping $(length(data)) bytes from the remote forwarded port"
    end

    return length(data)
end

function _on_client_channel_eof(session, sshchan, client)
    _logcb(client, "EOF")

    close(client.sshchan)
    if isopen(client.sock)
        closewrite(client.sock)
        close(client.sock)
    end
end

function _on_client_channel_close(session, sshchan, client)
    _logcb(client, "close")
end

# Handler for a single client on a forwarded port. It will take care of polling
# the channel and forwarding data to the server and client.
function _handle_forwarding_client(client)
    # Start polling the client channel
    poller = errormonitor(Threads.@spawn poll_loop(client.sshchan))

    # Read data from the socket while it's open
    sock = client.sock
    while isopen(sock)
        local data
        try
            # This will throw an IOError if the socket is closed during the read
            data = readavailable(sock)
        catch ex
            if ex isa Base.IOError
                continue
            else
                rethrow()
            end
        end

        if !isempty(data) && isopen(client.sshchan)
            write(client.sshchan, data)
        elseif isempty(data) && eof(sock)
            close(sock)
            if iswritable(client.sshchan)
                closewrite(client.sshchan)
            end
            close(client.sshchan)
        end
    end

    # This will throw if polling failed with an SSH_ERROR
    fetch(poller)
end

# Struct to represent a client connected to a forwarded port
mutable struct _ForwardingClient
    const id::Int
    verbose::Bool

    sock::TCPSocket
    sshchan::SshChannel
    callbacks::Callbacks.ChannelCallbacks
    client_task::Union{Task, Nothing}

    function _ForwardingClient(forwarder, socket::TCPSocket)
        remotehost = forwarder.remotehost
        remoteport = forwarder.remoteport

        # Open a forwarding channel
        local_ip = string(getaddrinfo(gethostname()))
        sshchan = SshChannel(forwarder._session)
        ret = _session_trywait(forwarder._session) do
            GC.@preserve remotehost local_ip begin
                lib.ssh_channel_open_forward(sshchan,
                                             Base.unsafe_convert(Ptr{Cchar}, remotehost), remoteport,
                                             Base.unsafe_convert(Ptr{Cchar}, local_ip), forwarder.localport)
            end
        end
        if ret != SSH_OK
            throw(LibSSHException("Could not open a forwarding channel: $(get_error(forwarder._session))"))
        end

        # Set callbacks for the channel
        callbacks = Callbacks.ChannelCallbacks(nothing;
                                               on_data=_on_client_channel_data,
                                               on_eof=_on_client_channel_eof,
                                               on_close=_on_client_channel_close)
        set_channel_callbacks(sshchan, callbacks)

        # Create a client and set the callbacks userdata to the new client object
        self = new(forwarder._next_client_id, forwarder.verbose, socket,
                   sshchan, callbacks, nothing)
        callbacks.userdata = self

        # Start a listener on the new socket to forward data to the server
        self.client_task = Threads.@spawn try
            _handle_forwarding_client(self)
        catch ex
            @error "Error when handling SSH port forward client $(self.id)!" exception=(ex, catch_backtrace())
        end

        return self
    end
end

# Helper function to log messages from a forwarding client
function _logcb(client::_ForwardingClient, msg)
    if client.verbose
        timestamp = Dates.format(Dates.now(), Dates.ISOTimeFormat)
        @info "$timestamp _ForwardingClient $(client.id): $msg"
    end
end

function Base.close(client::_ForwardingClient)
    # Check if the socket is open in a try-catch, because isopen() will throw an
    # exception if the socket isn't initialized yet by libuv.
    sock_isopen = true
    try
        sock_isopen = isopen(client.sock)
    catch ex
        if ex isa ArgumentError
            sock_isopen = false
        else
            rethrow()
        end
    end

    if sock_isopen
        if iswritable(client.sock)
            closewrite(client.sock)
        end
        close(client.sock)
    end

    close(client.sshchan)
    wait(client.client_task)
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

This object manages a direct forwarding channel between `localport` and
`remotehost:remoteport`. Fields beginning with an underscore `_` are private and
should not be used.
"""
@kwdef mutable struct Forwarder
    remotehost::String
    remoteport::Int
    localinterface::Sockets.IPAddr = Sockets.localhost
    localport::Int = -1

    out::Union{TCPSocket, Nothing} = nothing

    _listen_server::TCPServer = TCPServer()
    _listener_task::Union{Task, Nothing} = nothing
    _clients::Vector{_ForwardingClient} = _ForwardingClient[]
    _next_client_id::Int = 1

    _session::Session
    verbose::Bool
end

"""
$(TYPEDSIGNATURES)

Create a `Forwarder` object that will forward its data to a single
`TCPSocket`. This is useful if there is only one client and binding to a port
available to other processes is not desirable. The socket will be stored in the
`Forwarder.out` property, and it will be closed when the `Forwarder` is closed.

All arguments mean the same as in [`Forwarder(::Session, ::Int, ::String,
::Int)`](@ref).
"""
function Forwarder(session::Session, remotehost::String, remoteport::Int;
                   verbose=false)
    sock1, sock2 = _socketpair()
    self = Forwarder(; remotehost, remoteport, out=sock2, _session=session, verbose)
    push!(self._clients, _ForwardingClient(self, sock1))

    return self
end

"""
$(TYPEDSIGNATURES)

Create a `Forwarder` object to forward data from `localport` to
`remotehost:remoteport`. This will handle an internal [`SshChannel`](@ref)
for forwarding.

# Arguments
- `session`: The session to create a forwarding channel over.
- `localport`: The local port to bind to.
- `remotehost`: The remote host.
- `remoteport`: The remote port to bind to.
- `verbose`: Print logging messages on callbacks etc (not equivalent to
  setting `log_verbosity` on a [`Session`](@ref)).
- `localinterface=IPv4(0)`: The interface to bind `localport` on.
"""
function Forwarder(session::Session, localport::Int, remotehost::String, remoteport::Int;
                   verbose=false, localinterface::Sockets.IPAddr=IPv4(0))
    _listen_server = Sockets.listen(localinterface, localport)

    self = Forwarder(; remotehost, remoteport, localinterface, localport,
                     _listen_server, _session=session, verbose)

    # Start the listener
    self._listener_task = Threads.@spawn try
        _fwd_listen(self)
    catch ex
        @error "Error in listen loop for Forwarder!" exception=(ex, catch_backtrace())
    end

    finalizer(close, self)
end


function Base.show(io::IO, f::Forwarder)
    if !isopen(f)
        print(io, Forwarder, "([closed])")
    else
        if isnothing(f.out)
            print(io, Forwarder, "($(f.localinterface):$(f.localport) → $(f.remotehost):$(f.remoteport))")
        else
            print(io, Forwarder, "($(f.out) → $(f.remotehost):$(f.remoteport))")
        end
    end
end

"""
$(TYPEDSIGNATURES)

Do-constructor for a `Forwarder`. All arguments are forwarded to the other
constructors.
"""
function Forwarder(f::Function, args...; kwargs...)
    forwarder = Forwarder(args...; kwargs...)

    try
        return f(forwarder)
    finally
        close(forwarder)
    end
end

"""
$(TYPEDSIGNATURES)

Close a `Forwarder`. This will close all client channels and the listening local
socket.
"""
function Base.close(forwarder::Forwarder)
    # Stop accepting new clients
    close(forwarder._listen_server)
    if !isnothing(forwarder._listener_task)
        wait(forwarder._listener_task)
    end

    # Close existing clients
    for client in forwarder._clients
        close(client)
    end
end

function Base.isopen(forwarder::Forwarder)
    # If we're forwarding to a bound port then check if the TCPServer is
    # running, otherwise check if the single client socket is still open.
    if isnothing(forwarder.out)
        isopen(forwarder._listen_server)
    else
        isopen(forwarder.out)
    end
end

# This function accepts connections on the local port and sets up
# _ForwardingClient's for them.
function _fwd_listen(forwarder::Forwarder)
    while isopen(forwarder._listen_server)
        local sock
        try
            sock = Sockets.accept(forwarder._listen_server)
        catch ex
            if ex isa Base.IOError
                continue
            else
                rethrow()
            end
        end

        push!(forwarder._clients, _ForwardingClient(forwarder, sock))
        forwarder._next_client_id += 1
    end
end
