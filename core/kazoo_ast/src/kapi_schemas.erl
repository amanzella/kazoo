-module(kapi_schemas).

-export([process/0, process/1
        ,to_schemas/0, to_schema/1
        ]).

-include_lib("kazoo/include/kz_types.hrl").
-include_lib("kazoo_stdlib/include/kazoo_json.hrl").
-include_lib("kazoo_ast/include/kz_ast.hrl").
-include_lib("kazoo_amqp/src/api/kapi_presence.hrl").

-record(acc, {kapi_name :: ne_binary() %% s/kapi_(.+)/\1/
             ,api_name = <<"empty">> :: api_ne_binary() %% api function
             ,schemas = kz_json:new() :: kz_json:object()
             }).
-type acc() :: #acc{}.

-spec to_schemas() -> 'ok'.
-spec to_schema(module()) -> 'ok'.
to_schemas() ->
    lists:foreach(fun update_schema/1, process()).

to_schema(KapiModule) ->
    lists:foreach(fun update_schema/1, process(KapiModule)).

update_schema(GeneratedJObj) ->
    ID = kz_doc:id(GeneratedJObj),
    Path = kz_ast_util:schema_path(<<ID/binary, ".json">>),
    MergedJObj = kz_json:merge(fun kz_json:merge_left/2
                              ,existing_schema(Path)
                              ,GeneratedJObj
                              ),
    UpdatedSchema = kz_json:delete_key(<<"id">>, MergedJObj),
    'ok' = file:write_file(Path, kz_json:encode(UpdatedSchema)).

-spec existing_schema(file:filename_all()) -> kz_json:object().
existing_schema(Name) ->
    case kz_json_schema:fload(Name) of
        {'ok', JObj} -> JObj;
        {'error', 'not_found'} ->
            kz_json:new();
        {'error', _E} ->
            io:format("failed to find ~s: ~p~n", [Name, _E]),
            kz_json:new()
    end.

-spec process() -> acc().
-spec process(module()) -> acc().
process() ->
    io:format("process kapi modules: "),
    Options = [{'expression', fun expression_to_schema/2}
              ,{'function', fun set_function/2}
              ,{'module', fun print_dot/2}
              ,{'accumulator', #acc{}}
              ],
    #acc{schemas=Schemas} = kazoo_ast:walk_project(Options),
    io:format(" done~n", []),
    schemas_to_list(Schemas).

process(KapiModule) ->
    io:format("process kapi module ~s: ", [KapiModule]),
    Options = [{'expression', fun expression_to_schema/2}
              ,{'function', fun set_function/2}
              ,{'module', fun print_dot/2}
              ,{'accumulator', #acc{}}
              ],
    #acc{schemas=Schemas} = kazoo_ast:walk_modules([KapiModule], Options),
    io:format(" done~n", []),
    schemas_to_list(Schemas).

schemas_to_list(Schemas) ->
    kz_json:foldl(fun schema_api_to_list/3, [], Schemas).

schema_api_to_list(_KAPI, API, Acc0) ->
    kz_json:foldl(fun(_A, Schema, Acc) -> [Schema | Acc] end
                 ,Acc0
                 ,API
                 ).

-spec print_dot(ne_binary() | module(), acc()) ->
                       acc() |
                       {'skip', acc()}.
print_dot(<<"kapi_fs">>, #acc{}=Acc) ->
    {'skip', Acc};
print_dot(<<"kapi_", Module/binary>>, #acc{}=Acc) ->
    io:format("."),
    Acc#acc{kapi_name=Module};
print_dot(<<_/binary>>, #acc{}=Acc) ->
    {'skip', Acc};
print_dot(Module, #acc{}=Acc) ->
    print_dot(kz_term:to_binary(Module), Acc).

-spec set_function(ne_binary() | function(), acc()) -> acc().
set_function(<<_/binary>> = Function, #acc{}=Acc) ->
    case kz_binary:reverse(Function) of
        <<"v_", Nuf/binary>> ->
            Acc#acc{api_name=kz_binary:reverse(Nuf)};
        _ ->
            Acc#acc{api_name=Function}
    end;
set_function(Function, Acc) ->
    set_function(kz_term:to_binary(Function), Acc).

expression_to_schema(?MOD_FUN_ARGS('kz_api', 'build_message', [_Prop, Required, Optional]), Acc) ->
    properties_to_schema(kz_ast_util:ast_to_list_of_binaries(Required)
                        ,optional_validators(Optional)
                        ,Acc
                        );
expression_to_schema(?MOD_FUN_ARGS('kz_api', 'validate', [_Prop, _Required, Values, Types]), Acc) ->
    validators_to_schema(ast_to_proplist(Values), ast_to_proplist(Types), Acc);
expression_to_schema(_Expr, Acc) ->
    Acc.

optional_validators(?EMPTY_LIST) -> [];
optional_validators(Optional) ->
    kz_ast_util:ast_to_list_of_binaries(Optional).

properties_to_schema(RequiredHs, OptionalHs, #acc{kapi_name=KAPI
                                                 ,api_name=API
                                                 }=Acc) ->
    Schema = kapi_schema(Acc),
    {Required, OptHs} = just_required(RequiredHs),

    Optional = OptHs ++ OptionalHs,

    WithFields = lists:foldl(fun add_field/2, Schema, Required ++ Optional),

    Updated = kz_json:insert_values([{<<"_id">>, <<"kapi.", KAPI/binary, ".", API/binary>>}
                                    ,{<<"required">>, Required}
                                    ,{<<"$schema">>, <<"http://json-schema.org/draft-04/schema#">>}
                                    ,{<<"description">>, <<"AMQP API for ", KAPI/binary, ".", API/binary>>}
                                    ,{<<"properties">>, kz_json:new()}
                                    ,{<<"type">>, <<"object">>}
                                    ]
                                   ,WithFields
                                   ),
    set_kapi_schema(Acc, Updated).

%% see kapi_pusher for [Required, [Opt1, Opt2]]
just_required(Required) ->
    lists:foldl(fun flatten_required/2, {[], []}, Required).

flatten_required(<<_/binary>>=R, {Req, Opt}) ->
    {[R | Req], Opt};
flatten_required([R, <<_/binary>>=Optional], {Req, Opt}) ->
    {[R | Req], [Optional | Opt]};
flatten_required([R, Optional], {Req, Opt}) ->
    {[R | Req], Optional ++ Opt}.

kapi_schema(#acc{schemas=Schemas
                ,kapi_name=KAPI
                ,api_name=API
                }) ->
    kz_json:get_json_value([KAPI, API], Schemas, kz_json:new()).

set_kapi_schema(#acc{schemas=Schemas
                    ,kapi_name=KAPI
                    ,api_name=API
                    }=Acc, Schema) ->
    Acc#acc{schemas=kz_json:set_value([KAPI, API], Schema, Schemas)}.

add_field([_|_]=Fields, Schema) ->
    Path = lists:join(<<"properties">>, Fields),
    kz_json:insert_value(Path, kz_json:new(), Schema);
add_field(Field, Schema) ->
    add_field([Field], Schema).

validators_to_schema(Values, Types, Acc) ->
    Schema = lists:foldl(fun add_validator/2, kapi_schema(Acc), Values ++ Types),
    set_kapi_schema(Acc, Schema).

add_validator({Field, 'undefined'}, Schema) ->
    Properties = kz_json:get_json_value([<<"properties">>, Field], Schema, kz_json:new()),
    kz_json:set_value([<<"properties">>, Field], Properties, Schema);
add_validator({[_|_]=Fields, Value}, Schema) ->
    Path = lists:join(<<"properties">>, Fields),
    Properties = kz_json:get_json_value(Path, Schema, kz_json:new()),
    ValidatorProperties = validator_properties(Value),
    Updated = kz_json:merge(ValidatorProperties, Properties),
    kz_json:set_value(Path, Updated, Schema);
add_validator({Field, Value}, Schema) ->
    add_validator({[Field], Value}, Schema).

validator_properties(<<_/binary>>=Value) ->
    kz_json:from_list([{<<"type">>, <<"string">>}
                      ,{<<"enum">>, [Value]}
                      ]);
validator_properties([<<_/binary>>|_]=Values) ->
    kz_json:from_list([{<<"type">>, <<"string">>}
                      ,{<<"enum">>, Values}
                      ]);
validator_properties({_, 'is_integer', 1}) ->
    kz_json:from_list([{<<"type">>, <<"integer">>}]);
validator_properties({_, 'is_binary', 1}) ->
    kz_json:from_list([{<<"type">>, <<"string">>}]);
validator_properties({_, 'is_boolean', 1}) ->
    kz_json:from_list([{<<"type">>, <<"boolean">>}]);
validator_properties({_, 'is_list', 1}) ->
    kz_json:from_list([{<<"type">>, <<"array">>}]);
validator_properties({'kz_json', 'is_json_object', 1}) ->
    kz_json:from_list([{<<"type">>, <<"object">>}]);
validator_properties({'kz_term', 'is_boolean', 1}) ->
    kz_json:from_list([{<<"type">>, <<"boolean">>}]);
validator_properties({'kz_term', 'is_ne_binary', 1}) ->
    kz_json:from_list([{<<"type">>, <<"string">>}
                      ,{<<"minLength">>, 1}
                      ]);
validator_properties({'kapi_dialplan', 'terminators_v', 1}) ->
    kz_json:from_list([{<<"type">>, <<"array">>}
                      ,{<<"items">>
                       ,kz_json:from_list([{<<"type">>, <<"string">>}
                                          ,{<<"enum">>, ?ANY_DIGIT}
                                          ])
                       }
                      ]);
validator_properties({'kapi_dialplan', 'b_leg_events_v', 1}) ->
    kz_json:from_list([{<<"type">>, <<"array">>}
                      ,{<<"items">>
                       ,kz_json:from_list([{<<"type">>, <<"string">>}
                                          ,{<<"enum">>, ?CALL_EVENTS}
                                          ])
                       }
                      ]);
validator_properties({'function', 'b_leg_events_v', 1}) ->
    kz_json:from_list([{<<"type">>, <<"array">>}
                      ,{<<"items">>
                       ,kz_json:from_list([{<<"type">>, <<"string">>}
                                          ,{<<"enum">>, ?CALL_EVENTS}
                                          ])
                       }
                      ]);
validator_properties({'function', 'tone_timeout_v', 1}) ->
    kz_json:from_list([{<<"type">>, <<"integer">>}
                      ,{<<"minimum">>, 0}
                      ]);
validator_properties({'function', _F, _A}) ->
    io:format("  no properties for fun ~p~n", [_F]),
    kz_json:new().

ast_to_proplist(ASTList) ->
    ast_to_proplist(ASTList, []).

ast_to_proplist(?EMPTY_LIST, Acc) ->
    lists:reverse(Acc);
ast_to_proplist(?LIST(H, ?MOD_FUN_ARGS('props', 'delete', [ASTKey, ASTProps])), Acc) ->
    Key = kz_ast_util:binary_match_to_binary(ASTKey),
    Props = ast_to_proplist(ASTProps),
    [ast_to_kv(H) | props:set_values(props:delete(Key, Props), Acc)];
ast_to_proplist(?LIST(H, ?MOD_FUN_ARGS('props', 'delete_keys', [ASTKeys, ASTProps])), Acc) ->
    Keys = kz_ast_util:ast_to_list_of_binaries(ASTKeys),
    Props = ast_to_proplist(ASTProps),
    [ast_to_kv(H) | props:set_values(props:delete_keys(Keys, Props), Acc)];
ast_to_proplist(?LIST(H, T), Acc) ->
    ast_to_proplist(T, [ast_to_kv(H) | Acc]).

ast_to_kv(?TUPLE([Key, Value])) ->
    {kz_ast_util:binary_match_to_binary(Key)
    ,ast_to_value(Value)
    }.

ast_to_value(?MOD_FUN_ARGS('kapi_presence', 'presence_states', [])) ->
    ?PRESENCE_STATES;
ast_to_value(?BINARY(_)=Bin) ->
    kz_ast_util:binary_match_to_binary(Bin);
ast_to_value(?FA(F, A)) ->
    {'function', F, A};
ast_to_value(?MFA(M, F, A)) ->
    {M, F, A};
ast_to_value(?LIST(_, _)=ASTList) ->
    kz_ast_util:ast_to_list_of_binaries(ASTList);
ast_to_value(?ANON(Clauses)) ->
    clauses_to_value(Clauses);
ast_to_value(?VAR(_)) ->
    'undefined'.

clauses_to_value(?CLAUSE([?BINARY_STRING(Value)
                         ,?BINARY_VAR('_')
                         ]
                        ,_Guard
                        ,[?ATOM('true')])
                ) ->
    {'regex', list_to_binary([$^, kz_term:to_binary(Value), ".+$"])};
clauses_to_value(_Clause) -> 'undefined'.
