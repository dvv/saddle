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
  {error, badarg} |
  {error, scope} |
  {error, mismatch}.

%%
%% Validate client credentials for given scope.
%%
-callback authorize_client_credentials(
    ClientId :: binary(),
    ClientSecret :: binary(),
    Scope :: binary()) ->
  {ok, Identity :: term(), Scope2 :: binary()} |
  {error, badarg} |
  {error, scope} |
  {error, mismatch}.

%%
%% Verify correspondance of client and redirection URI.
%%
-callback verify_redirection_uri(
    ClientId :: binary(),
    RedirectUri :: binary()) ->
  ok |
  {error, badarg} |   % redirection URI does match client but smth else wrong
  {error, mismatch}.  % redirection URI doesn't match client

%%
%% Register a new client.
%%
-callback register_client(
    Identity :: binary(),
    RedirectUri :: binary(),
    Scope :: binary(),
    Options :: term()) ->
  {ok, ClientId :: binary(), ClientSecret :: binary()} |
  {error, badarg} |
  {error, scope}.

%%
%% Get info on given client.
%%
-callback validate_client(
    ClientId :: binary(),
    RedirectUri :: binary(),
    Scope :: binary(),
    Options :: term()) ->
  {ok, Data :: term()} |
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
