%% Copyright (c) 2011 Hunter Morris
%% Distributed under the MIT license; see LICENSE for details.
%% @doc The OpenBSD Blowfish password hashing algorithm wrapper module.
-module(bcrypt).
-author('Hunter Morris <hunter.morris@smarkets.com>').

%% API
-export([start/0, stop/0]).
-export([mechanism/0]).
-export([gen_salt/0, gen_salt/1, hashpw/2]).
-export([workers_available/0]).

-type mechanism() :: nif | port.
-type rounds() :: 4..31.
-type pwerr() :: invalid_salt | invalid_salt_length | invalid_rounds | timeout.

-export_type([ mechanism/0, rounds/0, pwerr/0 ]).

%% @doc Starts `Application' `bcrypt'. 
%% <b>See also:</b> 
%% [http://erlang.org/doc/man/application.html#start-1 application:start/1].

start() -> application:start(bcrypt).

%% @doc Stops `Application' `bcrypt'.  
%% <b>See also:</b> 
%% [http://erlang.org/doc/man/application.html#stop-1 application:stop/1].

stop()  -> application:stop(bcrypt).

%% @doc Get environment setting of hash generation.

-spec mechanism() -> mechanism().
mechanism() ->
    {ok, M} = application:get_env(bcrypt, mechanism),
    M.

%% @doc Returns a random string data.

-spec gen_salt() -> Result when
	Result :: {ok, Salt},
	Salt :: [byte()].
gen_salt() ->
    do_gen_salt(mechanism()).

%% @doc Generate a random string data.

-spec gen_salt( Rounds ) -> Result when
	Rounds :: rounds(),
	Result :: {ok, Salt},
	Salt :: [byte()].
gen_salt(Rounds) when is_integer(Rounds), Rounds < 32, Rounds > 3 ->
    gen_salt(Rounds, infinity).

-spec gen_salt( Rounds, Timeout ) -> Result when
	Rounds :: rounds(),
	Timeout :: timeout(),
	Result :: {ok, Salt} | {error, timeout},
	Salt :: [byte()].
gen_salt(Rounds, Timeout) when is_integer(Rounds), Rounds < 32, Rounds > 3 ->
	do_gen_salt(mechanism(), Rounds, Timeout).

%% @doc Make hash string based on `Password' and `Salt'.

-spec hashpw( Password, Salt ) -> Result when
	Password :: [byte()] | binary(), 
	Salt :: [byte()] | binary(),
	Result :: {ok, Hash} | {error, ErrorDescription},
	Hash :: [byte()],
	ErrorDescription :: pwerr().
hashpw(Password, Salt) ->
    hashpw(Password, Salt, infinity) .

%% @doc Make hash string based on `Password' and `Salt'.

-spec hashpw( Password, Salt, Timeout ) -> Result when
	Password :: [byte()] | binary(), 
	Salt :: [byte()] | binary(),
	Result :: {ok, Hash} | {error, ErrorDescription},
	Hash :: [byte()],
	Timeout :: timeout(),
	ErrorDescription :: pwerr().
hashpw(Password, Salt, Timeout) ->
    do_hashpw(mechanism(), Password, Salt, Timeout).

%% @doc Are any bcrypt workers currently available?

-spec workers_available() -> Result when
	Result :: boolean().
workers_available() ->
    do_workers_available(mechanism()).


%% @private

-spec do_workers_available(nif | port) -> Result when
	Result :: boolean().
do_workers_available(nif)  -> bcrypt_nif_worker:workers_available();
do_workers_available(port) -> bcrypt_pool:workers_available().

-spec do_gen_salt(nif | port) -> Result when
	Result :: {ok, Salt},
	Salt :: [byte()].
do_gen_salt(nif)  -> bcrypt_nif_worker:gen_salt();
do_gen_salt(port) -> bcrypt_pool:gen_salt().

%% @private

-spec do_gen_salt(nif | port, Rounds, Timeout) -> Result when
	Rounds :: rounds(),
	Timeout :: timeout(),
	Result :: {ok, Salt},
	Salt :: [byte()].
do_gen_salt(nif, Rounds, Timeout)  -> bcrypt_nif_worker:gen_salt(Rounds, Timeout);
do_gen_salt(port, Rounds, Timeout) -> bcrypt_pool:gen_salt(Rounds, Timeout).

%% @private

-spec do_hashpw(nif | port, Password, Salt, Timeout) -> Result when
	Password :: [byte()] | binary(), 
	Salt :: [byte()],
	Timeout :: timeout(),
	Result :: {ok, Hash} | {error, ErrorDescription},
	Hash :: [byte()],
	ErrorDescription :: pwerr().
do_hashpw(nif, Password, Salt, Timeout)  -> bcrypt_nif_worker:hashpw(Password, Salt, Timeout);
do_hashpw(port, Password, Salt, Timeout) -> bcrypt_pool:hashpw(Password, Salt, Timeout).
