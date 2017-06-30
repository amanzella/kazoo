-module(kapi_schemas).

-export([process/0
         %% ,to_schemas/0, to_schema/1
        ]).

-include_lib("kazoo/include/kz_types.hrl").
-include_lib("kazoo_stdlib/include/kazoo_json.hrl").
-include_lib("kazoo_ast/include/kz_ast.hrl").

%% #{"route" := #{"req" := {[properties]}}}
-type schema_map() :: #{ne_binary() := kz_json:object()}.
-type schemas_map() :: #{module() := schema_map()}.

-record(acc, {kapi_name :: ne_binary() %% s/kapi_(.+)/\1/
             ,api_name :: api_ne_binary() %% api function
             ,schemas = #{} :: schemas_map()
             }).
-type acc() :: #acc{}.

-spec process() -> acc().
process() ->
    io:format("process kapi modules: "),
    Options = [{'expression', fun expression_to_schema/2}
              ,{'function', fun set_function/2}
              ,{'module', fun print_dot/2}
              ,{'accumulator', []}
              ],
    Usage = kazoo_ast:walk_modules(['kapi_route'], Options),
    io:format(" done~n"),
    Usage.

-spec print_dot(ne_binary() | module(), acc()) ->
                       acc() |
                       {'skip', acc()}.
print_dot(<<"kapi_", _/binary>>=Module, Acc) ->
    io:format("."),
    Acc#acc{kapi_name=Module};
print_dot(<<_/binary>>, Acc) ->
    {'skip', Acc};
print_dot(Module, Acc) ->
    print_dot(kz_term:to_binary(Module), Acc).

set_function(F, #acc{api_name=Function}=Acc) ->
    FSize = byte_size(Function),
    case F of
        <<Function:FSize/binary, "_v">> ->
            io:format("  setting api name to ~s~n", [Function]),
            Acc#acc{api_name=Function};
        _ ->
            io:format("  setting api name to ~s~n", [Function]),
            Acc#acc{api_name=Function}
    end;
set_function(Function, Acc) ->
    set_function(kz_term:to_binary(Function), Acc).

expression_to_schema(?MOD_FUN_ARGS('kz_api', 'build_message', [_Prop, Required, Optional]), Acc) ->
    properties_to_schema(Required, Optional, Acc);
expression_to_schema(?MOD_FUN_ARGS('kz_api', 'validate', [_Prop, _Required, Values, Types]), Acc) ->
    validators_to_schema(Values, Types, Acc);
expression_to_schema(_Expr, Acc) ->
    Acc.

properties_to_schema(Required, Optional, #acc{schemas=Schemas
                                             ,kapi_name=KAPI
                                             ,api_name=API
                                             }=Acc) ->
    Schema = maps:get(API, maps:get(KAPI, Schemas, kz_json:new()), kz_json:new()),

    WithFields = lists:foldl(fun add_field/2, Schema, Required ++ Optional),

    Updated = kz_json:insert_values([{<<"_id">>, <<"kapi.", KAPI/binary, ".", API/binary>>}
                                    ,{<<"required">>, Required}
                                    ,{<<"$schema">>, <<"http://json-schema.org/draft-04/schema#">>}
                                    ,{<<"description">>, <<"AMQP API for ", KAPI/binary, ".", API/binary>>}
                                    ,{<<"properties">>, kz_json:object()}
                                    ,{<<"type">>, <<"object">>}
                                    ]
                                   ,WithFields
                                   ),
    Acc#acc{schemas=Schemas#{KAPI => #{API => Updated}}}.

add_field(Field, Schema) ->
    Properties = kz_json:get_json_value([<<"properties">>, Field], Schema),
    Updated = kz_json:merge(base_field_properties(Field), Properties),
    kz_json:set_value([<<"properties">>, Field], Updated, Schema).

base_field_properties(_Field) -> kz_json:new().

validators_to_schema(_Values, _Types, Acc) ->
    Acc.
