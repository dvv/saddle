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
