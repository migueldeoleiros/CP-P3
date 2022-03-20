-module(break_md5).
-define(PASS_LEN, 6).
-define(UPDATE_BAR_GAP, 100000).
-define(BAR_SIZE, 40).
-define(PROCESS, 5).

-export([break_md5/1,
         pass_to_num/1,
         num_to_pass/1,
         num_to_hex_string/1,
         hex_string_to_num/1,
         break_md5s/1
        ]).

-export([progress_loop/3,
         break_md5/5,
         start_procs/5
        ]).

% Base ^ Exp
pow_aux(_Base, Pow, 0) ->
    Pow;
pow_aux(Base, Pow, Exp) when Exp rem 2 == 0 ->
    pow_aux(Base*Base, Pow, Exp div 2);
pow_aux(Base, Pow, Exp) ->
    pow_aux(Base, Base * Pow, Exp - 1).

pow(Base, Exp) -> pow_aux(Base, 1, Exp).


%% Number to password and back conversion
num_to_pass_aux(_N, 0, Pass) -> Pass;
num_to_pass_aux(N, Digit, Pass) ->
    num_to_pass_aux(N div 26, Digit - 1, [$a + N rem 26 | Pass]).

num_to_pass(N) -> num_to_pass_aux(N, ?PASS_LEN, []).

pass_to_num(Pass) ->
    lists:foldl(fun (C, Num) -> Num * 26 + C - $a end, 0, Pass).


%% Hex string to Number
hex_char_to_int(N) ->
    if (N >= $0) and (N =< $9) -> N - $0;
       (N >= $a) and (N =< $f) -> N - $a + 10;
       (N >= $A) and (N =< $F) -> N - $A + 10;
       true                    -> throw({not_hex, [N]})
    end.

int_to_hex_char(N) ->
    if (N >= 0)  and (N < 10) -> $0 + N;
       (N >= 10) and (N < 16) -> $A + (N - 10);
       true                   -> throw({out_of_range, N})
    end.

hex_string_to_num(Hex_Str) ->
    lists:foldl(fun(Hex, Num) -> Num*16 + hex_char_to_int(Hex) end, 0, Hex_Str).

num_to_hex_string_aux(0, Str) -> Str;
num_to_hex_string_aux(N, Str) ->
    num_to_hex_string_aux(N div 16,
                          [int_to_hex_char(N rem 16) | Str]).

num_to_hex_string(0) -> "0";
num_to_hex_string(N) -> num_to_hex_string_aux(N, []).
   

%% Progress bar runs in its own process
progress_loop(N, Bound,T) ->
    receive
        stop -> ok;
        {progress_report, Checked} ->
            N2 = N + Checked,
            Full_N = N2 * ?BAR_SIZE div Bound,
            Full = lists:duplicate(Full_N, $=),
            Empty = lists:duplicate(?BAR_SIZE - Full_N, $-),
            T2 = erlang:monotonic_time(microsecond),
            T3 = T2-T,
            io:format("\r[~s~s] ~.2f% \t [~.2f op/sec]   ", [Full, Empty, N2/Bound*100,(Checked/T3)*1000000]),
            progress_loop(N2, Bound,T2)
    end.


%% break_md5/2 iterates checking the possible passwords
break_md5([], _, _, _, Start_Pid) -> ok; % Empty list of hashes (end of loop) 
break_md5(Hashes, N, N, _, Start_Pid) -> {not_found, Hashes};  % Checked every possible password
break_md5(Hashes, N, Bound, Progress_Pid, Start_Pid) ->
    receive 
        {remove, New_Hashes} ->
            break_md5(New_Hashes, N, Bound, Progress_Pid, Start_Pid);
        stop -> 
            ok
    after 0 ->
        if N rem ?UPDATE_BAR_GAP == 0 ->
                Progress_Pid ! {progress_report, ?UPDATE_BAR_GAP};
        true ->
                ok
        end,
        Pass = num_to_pass(N),
        Hash = crypto:hash(md5, Pass),
        Num_Hash = binary:decode_unsigned(Hash),
        case lists:member(Num_Hash, Hashes) of
            true ->
                io:format("\e[2K\r~.16B: ~s~n", [Num_Hash, Pass]),
                Start_Pid ! {found, lists:delete(Num_Hash, Hashes)},
                break_md5(lists:delete(Num_Hash, Hashes), N+1, Bound, Progress_Pid, Start_Pid);
            false ->
                break_md5(Hashes, N+1, Bound, Progress_Pid, Start_Pid)
        end
    end.


%% creates process with break_md5
start_procs(Hashes, 0, Bound, Progress_Pid, Break_List_Pid) ->
    receive
        stop -> 
            ok;
        {found,New_Hashes} ->
            Function = fun(Pid) -> 
                               Pid ! {remove, New_Hashes} 
                       end,
            lists:foreach(Function,Break_List_Pid),
            start_procs(Hashes, 0, Bound, Progress_Pid, Break_List_Pid)
    end;
        

start_procs(Hashes, N_Procs, Bound, Progress_Pid, Break_List_Pid) ->
    Start = Bound div ?PROCESS * (N_Procs-1),
    End   = Bound div ?PROCESS * N_Procs,
    Break_Pid = spawn(?MODULE, break_md5, [Hashes, Start, End, Progress_Pid, self()]),
    start_procs(Hashes, N_Procs-1, Bound, Progress_Pid, [Break_Pid | Break_List_Pid]).


%% Break one hash
break_md5(Hash) -> break_md5s([Hash]).

%% Breaks a list of hash
break_md5s(Hashes) ->
    Bound = pow(26, ?PASS_LEN),
    Progress_Pid = spawn(?MODULE, progress_loop, [0, Bound,0]),
    Num_Hashes = lists:map(fun hex_string_to_num/1, Hashes),
    Res = start_procs(Num_Hashes, ?PROCESS, Bound, Progress_Pid, []),
    Progress_Pid ! stop,
    Res.
