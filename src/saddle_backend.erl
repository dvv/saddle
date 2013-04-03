%%% ----------------------------------------------------------------------------
%%%
%%% @doc Skeleton for a security backend.
%%%
%%% ----------------------------------------------------------------------------

-module(saddle_backend).
-author('Vladimir Dronnikov <dronnikov@gmail.com>').

%%
%% Validate username and password of resource owner for given scope.
%%
-callback authorize_username_password(
    Username :: binary(),
    Password :: binary(),
    Scope :: binary()) ->
  {ok, Identity :: term(), Scope2 :: binary()} |
  {error, scope} |
  {error, mismatch}.

%%
%% Validate client credentials for given scope.
%% Parameter set to 'any' means do not check this parameter.
%%   This is used during some authorization flows (eg, implicit grant).
%%
-callback authorize_client_credentials(
    ClientId :: binary(),
    RedirectUri :: binary(),
    ClientSecret :: binary() | any,
    Scope :: binary() | any) ->
  {ok, Identity :: term(), Scope2 :: binary()} |
  {error, redirect_uri} |
  {error, scope} |
  {error, mismatch}.

%%
%% Register a new client.
%%
-callback register_client(
    Name :: binary(),
    RedirectUri :: binary(),
    Scope :: binary(),
    Options :: term()) ->
  {ok, ClientId :: binary()} |
  {error, badarg} |
  {error, scope}.

%%
%% Get info on given client.
%%
-callback validate_client(
    ClientId :: binary(),
    Secret :: binary()) ->
  {ok, RedirectUri :: binary(), Scope :: binary()} |
  {error, badarg}.

%%
%% Generate token.
%%
-callback register_token(
    Data :: term(),
    Options :: term()) ->
  Token :: binary().

%%
%% Validate token and retrieve info.
%% NB: this may possibly involve token revocation if token is one-time one.
%%
-callback validate_token(
    Token :: binary(),
    Options :: term()) ->
  {ok, Data :: term()} |
  {error, forged} |
  {error, expired}.
