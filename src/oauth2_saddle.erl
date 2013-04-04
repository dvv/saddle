%%% ----------------------------------------------------------------------------
%%%
%%% @doc Skeleton for a OAuth2 security backend.
%%%
%%% ----------------------------------------------------------------------------

-module(oauth2_saddle).
-author('Vladimir Dronnikov <dronnikov@gmail.com>').

-export([
    associate_access_code/2,
    associate_access_token/2,
    associate_refresh_token/2,
    authenticate_client/3,
    authenticate_username_password/3,
    get_identity/2,
    get_redirection_uri/1,
    resolve_access_code/1,
    resolve_access_token/1,
    resolve_refresh_token/1,
    revoke_access_code/1,
    revoke_access_token/1,
    revoke_refresh_token/1
  ]).

-export([
    generate/1
  ]).

associate_access_code(_AccessCode, _Context) ->
  % {error, notfound}.
  ok.

associate_access_token(_AccessToken, _Context) ->
  % {error, notfound}.
  ok.

associate_refresh_token(_RefreshToken, _Context) ->
  % {error, notfound}.
  ok.

authenticate_client(ClientId, _ClientSecret, Scope) ->
  % {error, notfound}.
  % {error, badsecret}.
  % {error, badscope}.
  {ok, {client, ClientId}, Scope}.

authenticate_username_password(Username, _Password, Scope) ->
  % {error, notfound}.
  % {error, badpass}.
  % {error, badscope}.
  {ok, {user, Username}, Scope}.

get_identity(ClientId, Scope) ->
  % {error, notfound}.
  % {error, badsecret}.
  % {error, badscope}.
  {ok, {client, ClientId}, Scope}.

get_redirection_uri(_ClientId) ->
  % {error, notfound}.
  {ok, <<"https://a6cypg.hopto.org/auth/native/callback">>}.


resolve_access_code(AccessCode) ->
  % {error, notfound}.
  termit:decode_base64(AccessCode, secret()).

resolve_access_token(AccessToken) ->
  % {error, notfound}.
  termit:decode_base64(AccessToken, secret()).

resolve_refresh_token(RefreshToken) ->
  % {error, notfound}.
  termit:decode_base64(RefreshToken, secret()).

revoke_access_code(_AccessCode) ->
  % {error, notfound}.
  ok.

revoke_access_token(_AccessToken) ->
  % {error, notfound}.
  ok.

revoke_refresh_token(_RefreshToken) ->
  % {error, notfound}.
  ok.

generate(Context) ->
  termit:encode_base64(Context, secret()).

secret() ->
  <<"foo">>.
