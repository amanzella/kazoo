%%%-------------------------------------------------------------------
%%% @copyright (C) 2010-2017, 2600Hz INC
%%% @doc
%%% @end
%%% @contributors
%%%   Pierre Fenoll
%%%-------------------------------------------------------------------
-module(kz_time_tests).

-include_lib("kazoo/include/kz_types.hrl").
-ifdef(PROPER).
-include_lib("proper/include/proper.hrl").
-endif.
-include_lib("eunit/include/eunit.hrl").

%% PROPER TESTING
-ifdef(PROPER).

prop_pretty_print_elapsed_s() ->
    ?FORALL({D, H, M, S}
           ,{non_neg_integer(), range(0,23), range(0, 59), range(0,59)}
           ,begin
                Seconds = (D * ?SECONDS_IN_DAY) + (H * ?SECONDS_IN_HOUR) + (M * ?SECONDS_IN_MINUTE) + S,
                Expected = lists:foldl(fun({0, "s"}, "") ->
                                               ["s", <<"0">>];
                                          ({0, _}, Acc) -> Acc;
                                          ({N, Unit}, Acc) -> [Unit, kz_term:to_binary(N) | Acc]
                                       end
                                      ,[]
                                      ,[{D, "d"}
                                       ,{H, "h"}
                                       ,{M, "m"}
                                       ,{S, "s"}
                                       ]),
                Result = kz_time:pretty_print_elapsed_s(Seconds),
                Result =:= iolist_to_binary(lists:reverse(Expected))
            end).

proper_test_() ->
    {"Runs the module's PropEr tests during eunit testing",
     {'timeout', 20000,
      [?_assertEqual([], proper:module(?MODULE, [{'to_file', 'user'}]))
      ]}}.

-endif.

to_x_test_() ->
    [?_assertEqual(true, kz_time:current_unix_tstamp() < kz_time:current_tstamp())
    ].

pretty_print_datetime_test_() ->
    TS = 63652662294,
    [?_assertEqual(<<"2017-01-26_15-04-54">>, kz_time:pretty_print_datetime(TS))
    ].

weekday_test_() ->
    Days = [<<"Mon">>, <<"Tue">>, <<"Wed">>, <<"Thu">>, <<"Fri">>, <<"Sat">>, <<"Sun">>],
    [?_assertEqual(lists:nth(I,Days), kz_time:weekday(I))
     || I <- lists:seq(1, 7)
    ].

month_test_() ->
    Months = [<<"Jan">>, <<"Feb">>, <<"Mar">>, <<"Apr">>, <<"May">>, <<"Jun">>
             ,<<"Jul">>, <<"Aug">>, <<"Sep">>, <<"Oct">>, <<"Nov">>, <<"Dec">>],
    [?_assertEqual(lists:nth(I,Months), kz_time:month(I))
     || I <- lists:seq(1, 12)
    ].

greg_secs_to_unix_secs_test() ->
    GregSecs = kz_time:current_tstamp(),
    ?assertEqual(GregSecs - ?UNIX_EPOCH_IN_GREGORIAN, kz_time:gregorian_seconds_to_unix_seconds(GregSecs)).

unix_secs_to_greg_secs_test() ->
    UnixSecs = 1000000000,
    ?assertEqual(UnixSecs + ?UNIX_EPOCH_IN_GREGORIAN, kz_time:unix_seconds_to_gregorian_seconds(UnixSecs)).

microsecs_to_secs_test() ->
    Microsecs = 1310157838405890,
    Secs = 1310157838,
    ?assertEqual(Secs, kz_time:microseconds_to_seconds(Microsecs)).

elapsed_test_() ->
    Start = {1401,998570,817606},
    Now = {1401,998594,798064},
    [?_assertEqual(23980458, kz_time:elapsed_us(Start, Now))
    ,?_assertEqual(23980, kz_time:elapsed_ms(Start, Now))
    ,?_assertEqual(23, kz_time:elapsed_s(Start, Now))
    ,?_assertEqual(<<"0s">>, kz_time:pretty_print_elapsed_s(0))
    ].

more_elapsed_test_() ->
    StartDateTime = {{2014,6,5},{20,7,7}},
    StartTimestamp = calendar:datetime_to_gregorian_seconds(StartDateTime),
    NowDateTime = {{2014,6,5},{20,7,9}},
    NowTimestamp = calendar:datetime_to_gregorian_seconds(NowDateTime),
    TS = 63652663232,
    [?_assertEqual(2, kz_time:elapsed_s(StartTimestamp, NowTimestamp))
    ,?_assertEqual(2000, kz_time:elapsed_ms(StartTimestamp, NowTimestamp))
    ,?_assertEqual(2000000, kz_time:elapsed_us(StartTimestamp, NowTimestamp))
    ,?_assertEqual(<<"2017-1-26">>, kz_time:format_date(TS))
    ,?_assertEqual(<<"15:20:32">>, kz_time:format_time(TS))
    ,?_assertEqual(<<"2017-1-26 15:20:32">>, kz_time:format_datetime(TS))
    ].

unitfy_and_timeout_test_() ->
    [?_assertEqual("", kz_time:unitfy_seconds(0))
    ,?_assertEqual(infinity, kz_time:decr_timeout(infinity, 0))
    ,?_assertEqual(0, kz_time:decr_timeout(30, 42))
    ,?_assertEqual(12, kz_time:decr_timeout(42, 30))
    ,?_assertEqual(10, kz_time:milliseconds_to_seconds(10*1000))
    ].

pad_month_test_() ->
    [?_assertEqual(<<"10">>, kz_time:pad_month(10))
    ,?_assertEqual(<<"10">>, kz_time:pad_month(<<"10">>))
    ,?_assertEqual(<<"03">>, kz_time:pad_month(3))
    ,?_assertEqual(<<"03">>, kz_time:pad_month(<<"3">>))
    ,?_assertEqual(<<"03">>, kz_time:pad_month(<<"03">>))
    ].

rfc1036_test_() ->
    Tests = [{{{2015,4,7},{1,3,2}}, <<"Tue, 07 Apr 2015 01:03:02 GMT">>}
            ,{{{2015,12,12},{12,13,12}}, <<"Sat, 12 Dec 2015 12:13:12 GMT">>}
            ,{63595733389, <<"Wed, 08 Apr 2015 17:29:49 GMT">>}
            ],
    [?_assertEqual(Expected, kz_time:rfc1036(Date))
     || {Date, Expected} <- Tests
    ].

iso8601_test_() ->
    Tests = [{{2015,4,7}, <<"2015-04-07">>}
            ,{{{2015,4,7},{0,0,0}}, <<"2015-04-07">>}
            ,{{{2015,4,7},{1,3,2}}, <<"2015-04-07T01:03:02">>}
            ,{{{2015,12,12},{12,13,12}}, <<"2015-12-12T12:13:12">>}
            ,{63595733389, <<"2015-04-08T17:29:49">>}
            ],
    [?_assertEqual(Expected, kz_time:iso8601(Date))
     || {Date, Expected} <- Tests
    ].

iso8601_date_test_() ->
    Tests = [{{2015,4,7}, <<"2015-04-07">>}
            ,{{{2015,4,7},{0,0,0}}, <<"2015-04-07">>}
            ,{{{2015,4,7},{1,3,2}}, <<"2015-04-07">>}
            ,{{{2015,12,12},{12,13,12}}, <<"2015-12-12">>}
            ,{63595733389, <<"2015-04-08">>}
            ],
    [?_assertEqual(Expected, kz_time:iso8601_date(Date))
     || {Date, Expected} <- Tests
    ].

to_gregorian_seconds_test_() ->
    Datetime = {{2017,04,01}, {12,0,0}},
    LASeconds = kz_time:to_gregorian_seconds(Datetime, undefined),
    NYSeconds = kz_time:to_gregorian_seconds(Datetime, <<"America/New_York">>),
    [?_assertEqual(63658292400, LASeconds)
    ,?_assertEqual(63658281600, NYSeconds)
    ].
