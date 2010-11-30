%%%-------------------------------------------------------------------
%%% @author Karl Anderson <karl@2600hz.com>
%%% @copyright (C) 2010, Karl Anderson
%%% @doc
%%% Responsible for runnning the network monitoring tasks
%%% @end
%%% Created : 11 Nov 2010 by Karl Anderson <karl@2600hz.com>
%%%-------------------------------------------------------------------
-module(monitor_agent_network).

-behaviour(gen_server).

%% API
-export([start_link/1]).

-export([set_amqp_host/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
     terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-import(logger, [format_log/3]).
-import(proplists, [get_value/2, get_value/3]).

-include("../include/monitor_amqp.hrl").

-record(state, {
        amqp_host = "" :: string()
        ,agent_q = <<>> :: binary()
    }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(AHost) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [AHost], []).

set_amqp_host(AHost) ->
    gen_server:call(?SERVER, {set_amqp_host, AHost}, infinity).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([AHost]) ->
    format_log(info, "MONITOR_AGENT_NETWORK(~p): Starting server with amqp host ~p~n", [self(), AHost]),
    {ok, Agent_Q} = start_amqp(AHost),
    {ok, #state{amqp_host=AHost, agent_q=Agent_Q}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({set_amqp_host, AHost}, _From, #state{amqp_host=CurrentAHost, agent_q=CurrentAgentQ}=State) ->
    format_log(info, "MONITOR_AGENT_NETWORK(~p): Updating amqp host from ~p to ~p~n", [self(), CurrentAHost, AHost]),
    amqp_util:queue_delete(CurrentAHost, CurrentAgentQ),
    amqp_manager:close_channel(self(), CurrentAHost),
    {ok, Agent_Q} = start_amqp(AHost),
    {reply, ok, State#state{amqp_host=AHost, agent_q=Agent_Q}};
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info({'EXIT', _Pid, Reason}, State) ->
    format_log(error, "MONITOR_AGENT_NETWORK(~p): Received EXIT(~p) from ~p...~n", [self(), Reason, _Pid]),
    {noreply, Reason, State};
%% Spawn tasks to process the incomming requests
handle_info({_, #amqp_msg{props = Props, payload = Payload}}, State) ->
    spawn(fun() -> handle_req(Props#'P_basic'.content_type, Payload, State) end),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, #state{amqp_host=AHost, agent_q=Agent_Q}) ->
    amqp_util:queue_delete(AHost, Agent_Q),
    format_log(error, "MONITOR_AGENT_NETWORK(~p): Killed queue, going down(~p)...~n", [self(), _Reason]),
    ok;
terminate(_Reason, _State) ->
    format_log(error, "MONITOR_AGENT_NETWORK(~p): Going down(~p)...~n", [self(), _Reason]),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
start_amqp(AHost) ->
    amqp_util:monitor_exchange(AHost),
    amqp_util:targeted_exchange(AHost),

    Agent_Q = amqp_util:new_monitor_queue(AHost),

    %% Bind the queue to the targeted exchange
    format_log(info, "MONITOR_AGENT_NETWORK(~p): Bind ~p as a targeted queue~n", [self(), Agent_Q]),
    amqp_util:bind_q_to_targeted(AHost, Agent_Q),

    %% Bind the queue to the topic exchange
    format_log(info, "MONITOR_AGENT_NETWORK(~p): Bind ~p for ~p~n", [self(), Agent_Q, ?KEY_AGENT_NET_REQ]),
    amqp_util:bind_q_to_monitor(AHost, Agent_Q, ?KEY_AGENT_NET_REQ),

    %% Register a consumer to listen to the queue
    format_log(info, "MONITOR_AGENT_NETWORK(~p): Consume on ~p~n", [self(), Agent_Q]),
    amqp_util:basic_consume(AHost, Agent_Q),

    {ok, Agent_Q}.

get_msg_type(Prop) ->
    { get_value(<<"Event-Category">>, Prop), get_value(<<"Event-Name">>, Prop) }.

get_msg_destination(Prop) ->
     Dest = get_value(<<"Destination">>, Prop, <<"localhost">>),
     binary_to_list(Dest).

handle_req(ContentType, Payload, State) ->
    case ContentType of
    <<"application/json">> ->
        {struct, Prop} = mochijson2:decode(binary_to_list(Payload)),
        format_log(info, "MONITOR_AGENT_NETWORK(~p): Recv CT: ~p~nPayload: ~p~n", [self(), ContentType, Prop]),
        process_req(get_msg_type(Prop), Prop, State);
    _ ->
        format_log(info, "MONITOR_AGENT_NETWORK(~p): recieved unknown msg type: ~p~n", [self(), ContentType])
    end.

process_req({<<"task">>, <<"ping_net_req">>}, Prop, State) ->
    case monitor_api:ping_net_req_v(Prop) of
    true ->
        Resp = monitor_icmp:ping_test(get_msg_destination(Prop)),
        create_send_ping_resp(Resp, Prop, State);
    _ ->
        format_log(error, "MONITOR_AGENT_NETWORK.ping(~p): Failed to validate ping_net_req~n", [self()])
    end,
    State;
process_req(_MsgType, _Prop, _State) ->
    format_log(info, "MONITOR_AGENT_NETWORK(~p): Unhandled Msg ~p~nJSON: ~p~n", [self(), _MsgType, _Prop]).

create_send_ping_resp(Resp, Prop, #state{amqp_host=AHost, agent_q=Agent_Q})->
    RespQ = get_value(<<"Server-ID">>, Prop),
    Defaults = monitor_util:prop_updates([{<<"Server-ID">>, Agent_Q}, {<<"Event-Name">>, <<"ping_net_resp">>}], Prop),
    Headers = monitor_api:prepare_amqp_prop([Resp, Defaults]),
    format_log(info, "MONITOR_AGENT_NETWORK(~p): Created reply headers:~nPayload: ~p~n", [self(), Headers]),
    {ok, JSON} = monitor_api:ping_net_resp(Headers),
    send_resp(JSON, RespQ, AHost).

send_resp(JSON, RespQ, AHost) ->
    format_log(info, "MONITOR_AGENT_NETWORK(~p): Sending reply to ~p~n", [self(), RespQ]),
    amqp_util:targeted_publish(AHost, RespQ, JSON, <<"application/json">>).
