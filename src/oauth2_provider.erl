%%% ----------------------------------------------------------------------------
%%%
%%% @doc OAuth2 provider.
%%%
%%% ----------------------------------------------------------------------------

-module(oauth2_provider).
-author('Vladimir Dronnikov <dronnikov@gmail.com>').

% -behaviour(cowboy_rest_handler).
-export([
    init/3,
    terminate/3,
    rest_init/2,
    allowed_methods/2,
    content_types_accepted/2,
    content_types_provided/2,
    post_is_create/2
  ]).

% getters
-export([
    get_resource/2
  ]).

% setters
-export([
    put_form/2,
    put_json/2
  ]).

-record(state, {
    options,
    data,
    backend,
    client_id,
    client_secret,
    redirect_uri,
    scope,
    opaque,
    response_type
  }).

init(_Transport, Req, Opts) ->
  {_, Backend} = lists:keyfind(backend, 1, Opts),
  {upgrade, protocol, cowboy_rest, Req, #state{
      options = Opts,
      backend = Backend
    }}.

terminate(_Reason, _Req, _State) ->
  ok.

rest_init(Req, State) ->
  {ok, Req, State}.

allowed_methods(Req, State) ->
  {[<<"GET">>, <<"POST">>], Req, State}.

content_types_accepted(Req, State) ->
  {[
    {{<<"application">>, <<"json">>, []}, put_json},
    {{<<"application">>, <<"x-www-form-urlencoded">>, []}, put_form}
  ], Req, State}.

content_types_provided(Req, State) ->
  {[
    {{<<"application">>, <<"json">>, []}, get_resource},
    {{<<"text">>, <<"html">>, []}, get_resource}
  ], Req, State}.

%%------------------------------------------------------------------------------
%% Authorization Request
%%------------------------------------------------------------------------------

get_resource(Req, State) ->
  case cowboy_req:qs_val(<<"client_id">>, Req) of
    {undefined, Req2} ->
      fail(Req2, State#state{data = [
          {error, <<"invalid_request">>},
          {error_description, <<"missing client_id">>}]});
    {ClientId, Req2} ->
      get_redirection_uri(Req2, State#state{client_id = ClientId})
  end.

get_redirection_uri(Req, State) ->
  case cowboy_req:qs_val(<<"redirect_uri">>, Req) of
    {undefined, Req2} ->
      fail(Req2, State#state{data = [
          {error, <<"invalid_request">>},
          {error_description, <<"missing redirect_uri">>}]});
    {RedirectUri, Req2} ->
      check_redirection_uri(Req2, State#state{redirect_uri = RedirectUri})
  end.

check_redirection_uri(Req, State = #state{client_id = ClientId,
    redirect_uri = RedirectUri, backend = Backend}) ->
  {Opaque, Req2} = cowboy_req:qs_val(<<"state">>, Req, <<>>),
  case Backend:verify_redirection_uri(ClientId, RedirectUri) of
    ok ->
      check_response_type(Req2, State#state{
          opaque = Opaque});
    % NB: do not redirect to unauthorized URI
    {error, redirect_uri} ->
      fail(Req2, State#state{data = <<"unauthorized_client">>,
          redirect_uri = undefined, opaque = Opaque});
    % NB: do not redirect to unauthorized URI
    {error, mismatch} ->
      fail(Req2, State#state{data = <<"unauthorized_client">>,
          redirect_uri = undefined, opaque = Opaque});
    % another validation error
    {error, badarg} ->
      fail(Req2, State#state{opaque = Opaque, data = [
          {error, <<"invalid_request">>},
          {error_description, <<"invalid redirect_uri">>}]})
  end.

check_response_type(Req, State) ->
  case cowboy_req:qs_val(<<"response_type">>, Req) of
    {<<"code">>, Req2} ->
      check_scope(Req2, State#state{response_type = <<"code">>});
    {<<"token">>, Req2} ->
      check_scope(Req2, State#state{response_type = <<"token">>});
    {_, Req2} ->
      fail(Req2, State#state{data = <<"unsupported_response_type">>})
  end.

check_scope(Req, State = #state{client_id = ClientId, backend = Backend}) ->
  {Scope, Req2} = cowboy_req:qs_val(<<"scope">>, Req),
  case Backend:authorize_client_credentials(ClientId, implicit, Scope) of
    {ok, _, Scope2} ->
      authorization_decision(Req2, State#state{scope = Scope2});
    {error, scope} ->
      fail(Req, State#state{data = <<"invalid_scope">>});
    {error, _} ->
      fail(Req, State#state{data = <<"invalid_request">>})
  end.

%%------------------------------------------------------------------------------
%% Authorization Response
%%------------------------------------------------------------------------------

%%
%% @todo this route per se must be accessible by authenticated resourse owners!
%%

%%
%% @todo no-cache for these two
%%

authorization_decision(Req, State = #state{response_type = <<"code">>,
    client_id = ClientId, redirect_uri = RedirectUri,
    scope = Scope, opaque = Opaque,
    backend = Backend, options = Opts
  }) ->
  % respond with form containing authorization code.
  % NB: flow continues after form submit ok
  Code = Backend:register_token({code, Opaque, ClientId, RedirectUri, Scope},
      {key(code_secret, Opts), key(code_ttl, Opts)}),
  {<<
      "<p>Client: \"", ClientId/binary, "\" asks permission for scope:\"", Scope/binary, "\"</p>",
      "<form action=\"", RedirectUri/binary, "\" method=\"get\">",
      "<input type=\"hidden\" name=\"code\" value=\"", Code/binary, "\" />",
      "<input type=\"hidden\" name=\"state\" value=\"", Opaque/binary, "\" />",
      "<input type=\"submit\" value=\"ok\" />",
      "</form>",
      "<form action=\"", RedirectUri/binary, "\" method=\"get\">",
      "<input type=\"hidden\" name=\"error\" value=\"access_denied\" />",
      "<input type=\"hidden\" name=\"state\" value=\"", Opaque/binary, "\" />",
      "<input type=\"submit\" value=\"nak\" />",
      "</form>"
    >>, Req, State};

authorization_decision(Req, State = #state{response_type = <<"token">>,
    client_id = ClientId, redirect_uri = RedirectUri,
    scope = Scope, opaque = Opaque, options = Opts
  }) ->
  % NB: client already implicitly authorized at this point
  % respond with form containing token
  Token = urlencode(token(ClientId, Scope, Opts)),
  {<<
      "<p>Client: \"", ClientId/binary, "\" asks permission for scope:\"", Scope/binary, "\"</p>",
      "<form action=\"", RedirectUri/binary, "#", Token/binary, "&state=", Opaque/binary, "\" method=\"get\">",
      "<input type=\"submit\" value=\"ok\" />",
      "</form>",
      "<form action=\"", RedirectUri/binary, "#error=access_denied&state=", Opaque/binary, "\" method=\"get\">",
      "<input type=\"submit\" value=\"nak\" />",
      "</form>"
    >>, Req, State}.

%%------------------------------------------------------------------------------
%% Error Response
%%------------------------------------------------------------------------------

fail(Req, State = #state{data = Error}) when is_binary(Error) ->
  fail(Req, State#state{data = [{error, Error}]});
%% no redirect_uri is known or it's invalid -> respond with error
fail(Req, State = #state{data = Error, redirect_uri = undefined}) ->
  {ok, Req2} = cowboy_req:reply(400, [
      {<<"content-type">>, <<"application/json; charset=UTF-8">>},
      {<<"cache-control">>, <<"no-store">>},
      {<<"pragma">>, <<"no-cache">>}
    ], jsx:encode(Error), Req),
  {halt, Req2, State};
%% redirect_uri is valid -> pass error to redirect_uri as fragment
fail(Req, State = #state{data = Error, response_type = <<"token">>,
    redirect_uri = RedirectUri, opaque = Opaque}) ->
  % redirect to redirect URI with data urlencoded
  {ok, Req2} = cowboy_req:reply(302, [
      {<<"location">>, << RedirectUri/binary, $#,
            (urlencode([{state, Opaque} | Error]))/binary >>},
      {<<"cache-control">>, <<"no-store">>},
      {<<"pragma">>, <<"no-cache">>}
    ], <<>>, Req),
  {halt, Req2, State};
%% redirect_uri is valid -> pass error to redirect_uri as querystring
fail(Req, State = #state{data = Error,
    redirect_uri = RedirectUri, opaque = Opaque}) ->
  % redirect to redirect URI with data urlencoded
  {ok, Req2} = cowboy_req:reply(302, [
      {<<"location">>, << RedirectUri/binary, $?,
            (urlencode([{state, Opaque} | Error]))/binary >>},
      {<<"cache-control">>, <<"no-store">>},
      {<<"pragma">>, <<"no-cache">>}
    ], <<>>, Req),
  {halt, Req2, State}.

%%------------------------------------------------------------------------------
%% Access Token Request
%%------------------------------------------------------------------------------

post_is_create(Req, State) ->
  {true, Req, State}.

put_json(Req, State) ->
  {ok, JSON, Req2} = cowboy_req:body(Req),
  case jsx:decode(JSON, [{error_handler, fun(_, _, _) -> {error, badarg} end}])
  of
    {error, _} ->
      {false, Req2, State};
    {incomplete, _} ->
      {false, Req2, State};
    Data ->
      request_token(Req2, State#state{data = Data})
  end.

put_form(Req, State) ->
  {ok, Data, Req2} = cowboy_req:body_qs(Req),
  request_token(Req2, State#state{data = Data}).

request_token(Req, State = #state{data = Data}) ->
  case lists:keyfind(<<"grant_type">>, 1, Data) of
    {_, <<"authorization_code">>} ->
      authorization_code_flow_stage2(Req, State);
    {_, <<"refresh_token">>} ->
      redeem_refresh_token(Req, State);
    {_, <<"password">>} ->
      password_credentials_flow(Req, State);
    {_, <<"client_credentials">>} ->
      client_credentials_flow(Req, State);
    _ ->
      fail(Req, State#state{data = <<"unsupported_grant_type">>})
  end.

%%------------------------------------------------------------------------------
%% Access Token Response
%%------------------------------------------------------------------------------

%%
%% Exchange authorization code for access token.
%%
authorization_code_flow_stage2(Req, State = #state{
    data = Data, options = Opts, backend = Backend
  }) ->
  ClientId = key(<<"client_id">>, Data),
  ClientSecret = key(<<"client_secret">>, Data),
  RedirectUri = key(<<"redirect_uri">>, Data),
  % decode authorization code, ensure its validity
  % NB: code is expired after code_ttl seconds since issued
  case Backend:validate_token(key(<<"code">>, Data), key(code_secret, Opts)) of
    {ok, {code, _, ClientId, RedirectUri, Scope}} ->
      % authorize client and get authorized scope
      case Backend:authorize_client_credentials(
          ClientId, ClientSecret, Scope)
      of
        {ok, Identity, Scope2} ->
          % respond with token
          % NB: can also issue refresh token
          issue_token(Req, State, Identity, Scope2);
        {error, scope} ->
          fail(Req, State#state{data = <<"invalid_scope">>});
        {error, _} ->
          fail(Req, State#state{data = <<"unauthorized_client">>})
      end;
    {ok, _} ->
      fail(Req, State#state{data = <<"invalid_grant">>});
    {error, _} ->
      fail(Req, State#state{data = <<"invalid_grant">>})
  end.

%%
%% Refresh an access token.
%%
redeem_refresh_token(Req, State = #state{data = Data,
    backend = Backend, options = Opts}) ->
  % NB: token is expired after refresh_ttl seconds since issued
  try Backend:validate_token(key(<<"refresh_token">>, Data),
      key(refresh_secret, Opts))
  of
    {ok, {refresh_token, Identity, Scope}} ->
      issue_token(Req, State, Identity, Scope);
    {ok, _} ->
      fail(Req, State#state{data = <<"invalid_grant">>});
    {error, _} ->
      fail(Req, State#state{data = <<"invalid_grant">>})
  catch _:_ ->
    fail(Req, State#state{data = <<"invalid_request">>})
  end.

%%
%% Request access token for a resource owner.
%%
password_credentials_flow(Req, State = #state{
    data = Data, backend = Backend}) ->
  % @todo ensure scheme is https
  try Backend:authorize_username_password(
      key(<<"username">>, Data),
      key(<<"password">>, Data),
      key(<<"scope">>, Data))
  of
    {ok, Identity, Scope} ->
      issue_token(Req, State, Identity, Scope);
    {error, scope} ->
      fail(Req, State#state{data = <<"invalid_scope">>});
    {error, _} ->
      fail(Req, State#state{data = <<"access_denied">>})
  catch _:_ ->
    fail(Req, State#state{data = <<"invalid_request">>})
  end.

%%
%% Request access code for a client.
%%
client_credentials_flow(Req, State = #state{data = Data, backend = Backend}) ->
  % @todo ensure scheme is https
  try Backend:authorize_client_credentials(
      key(<<"client_id">>, Data),
      key(<<"client_secret">>, Data),
      key(<<"scope">>, Data))
  of
    {ok, Identity, Scope} ->
      % NB: no refresh token should be issued
      issue_token(Req, State, Identity, Scope);
    {error, scope} ->
      fail(Req, State#state{data = <<"invalid_scope">>});
    {error, _} ->
      fail(Req, State#state{data = <<"unauthorized_client">>})
  catch _:_ ->
    fail(Req, State#state{data = <<"invalid_request">>})
  end.

%%
%% Respond with access token.
%%
issue_token(Req, State = #state{options = Opts}, Identity, Scope) ->
  {ok, Req2} = cowboy_req:reply(200, [
      {<<"content-type">>, <<"application/json; charset=UTF-8">>},
      {<<"cache-control">>, <<"no-store">>},
      {<<"pragma">>, <<"no-cache">>}
    ], jsx:encode(token(Identity, Scope, Opts)), Req),
  {halt, Req2, State}.

token(Identity, Scope, Opts) ->
  Backend = key(backend, Opts),
  AccessToken = Backend:register_token({access_token, Identity, Scope},
      {key(token_secret, Opts), key(token_ttl, Opts)}),
  [
    {access_token, AccessToken},
    {token_type, <<"bearer">>},
    {expires_in, key(token_ttl, Opts)},
    {scope, Scope}
  ].

% token(Identity, Scope, Opts, with_refresh) ->
%   Backend = key(backend, Opts),
%   AccessToken = Backend:register_token({access_token, Identity, Scope},
%       {key(token_secret, Opts), key(token_ttl, Opts)}),
%   RefreshToken = Backend:register_token({refresh_token, Identity, Scope},
%       {key(refresh_secret, Opts), key(refresh_ttl, Opts)}),
%   [
%     {access_token, AccessToken},
%     {token_type, <<"Bearer">>},
%     {expires_in, key(token_ttl, Opts)},
%     {scope, Scope},
%     {refresh_token, RefreshToken}
%   ].

%%
%% -----------------------------------------------------------------------------
%% Helpers
%% -----------------------------------------------------------------------------
%%

key(Key, List) ->
  {_, Value} = lists:keyfind(Key, 1, List),
  Value.

urlencode(Bin) when is_binary(Bin) ->
  cowboy_http:urlencode(Bin);
urlencode(Atom) when is_atom(Atom) ->
  urlencode(atom_to_binary(Atom, latin1));
urlencode(Int) when is_integer(Int) ->
  urlencode(list_to_binary(integer_to_list(Int)));
urlencode({K, undefined}) ->
  << (urlencode(K))/binary, $= >>;
urlencode({K, V}) ->
  << (urlencode(K))/binary, $=, (urlencode(V))/binary >>;
urlencode(List) when is_list(List) ->
  binary_join([urlencode(X) || X <- List], << $& >>).

binary_join([], _Sep) ->
  <<>>;
binary_join([H], _Sep) ->
  << H/binary >>;
binary_join([H | T], Sep) ->
  << H/binary, Sep/binary, (binary_join(T, Sep))/binary >>.
