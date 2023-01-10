import os
import pickle
from collections import OrderedDict
from matplotlib import pyplot as plt
import math

from class_definitions import SyscallTracesResult, SignatureMatchResult


ANALYSIS_RESULTS_FILE = 'results/syscall_traces_results.pkl'
SIGNATURE_MATCH_RESULTS_FILE = 'results/signature_match_results.pkl'


# Cache dei risultati ottenuti dalle analisi
# Mappa [mimikatz_module:str, session_name:str] -> result:SyscallTracesResult
__syscall_results = {}
if os.path.isfile(ANALYSIS_RESULTS_FILE):
    with open(ANALYSIS_RESULTS_FILE, 'rb') as __analysis_db:
        __syscall_results = pickle.load(__analysis_db)
        print('[*] Syscall analysis database was found and loaded')

# Cache dei risultati ottenuti dalla verifica delle signature
# Mappa [mimikatz_module:str, session_name:str, tracefile:str, strategy:str] -> result:SignatureCheckResult
__signature_results = {}
if os.path.isfile(SIGNATURE_MATCH_RESULTS_FILE):
    with open(SIGNATURE_MATCH_RESULTS_FILE, 'rb') as __match_db:
        __signature_results = pickle.load(__match_db)
        print('[*] Signature matches database was found and loaded')


def parse_syscalls_log(logfile):
    """
    Estrazione della sequenza di system calls dal file di log generato da drstrace

    :param logfile Il path del file di log da analizzare
    :return Una lista di tuple (nome_syscall, num. invocazioni consecutive, num. successi, num. errori)
    """

    # Lista di tuple (nome syscall, num. invocazioni consecutive, num. successi, num. errori)
    syscalls = []
    current_syscall = None
    n_calls = 0
    n_successes = 0
    n_failures = 0

    with open(logfile, 'r') as input_log:

        for line_num, line in enumerate(input_log):

            # Nome della syscall
            if line[0].isalpha() or line.startswith('<unknown>'):

                next_syscall = line.strip()
                next_syscall = next_syscall.split(" ")[0]

                if next_syscall == current_syscall:
                    n_calls += 1

                else:

                    if current_syscall is not None:
                        syscalls.append((current_syscall, n_calls, n_successes, n_failures))

                    current_syscall = next_syscall
                    n_calls = 1
                    n_successes = 0
                    n_failures = 0

            # Argomenti della syscall, non ci interessano
            elif line.startswith('\t'):
                continue

            # Fix per delle entry nel file di log generate da drstrace che non ci interessano
            elif line.startswith('<unnamed-type-Share>') or line.startswith('_FILE_REMOTE_PROTOCOL_INFORMATION'):
                continue

            # Esito della syscall (success/failure)
            elif line.startswith(' '):

                outcome = line.strip()[:-3].split(' ')[0]  # eliminiamo " =>" ed eventuale codice d'errore
                if outcome == 'succeeded':
                    n_successes += 1
                elif outcome == 'failed':
                    n_failures += 1
                else:
                    raise RuntimeError(f'Formato dei log di input inatteso, alla riga #{line_num} ho letto: {line}')

            # Non dovrebbe succedere, a meno che non ci sia sfuggito qualche dettaglio sul formato dei log
            else:
                raise RuntimeError(f'Formato dei log di input inatteso, alla riga #{line_num} ho letto: {line}')

        syscalls.append((current_syscall, n_calls, n_successes, n_failures))

        return tuple(syscalls)


def check_signature_in_tracefile(mimikatz_module, session_name, trace_filename, strategy='strict'):
    """Confronta la signature data con la syscall trace contenuta nel file dato.

    :param mimikatz_module Il modulo di Mimikatz di interesse
    :param session_name La sessione utilizzata per generare la signature che si desidera confrontare
    :param trace_filename Il nome del file contente la trace delle syscall da analizzare
    :param strategy La strategia da utilizzare per il check della signature, 'strict' o 'lax'
    :return La lunghezza del match tra la signature e il tracefile per ciascun offset
    """

    global __signature_results, __syscall_results

    try:
        signature_sequence = __syscall_results[mimikatz_module, session_name].signature
    except KeyError:
        raise KeyError(f'La signature richiesta [{mimikatz_module}::{session_name}] non è ancora stata generata')

    try:
        results = __signature_results[mimikatz_module, session_name, trace_filename, strategy]
        return results
    except KeyError:
        pass

    # Otteniamo la sequenza di syscall contenuta nel file di trace
    trace_sequence = [entry[0] for entry in parse_syscalls_log(trace_filename)]

    # Filtriamo le syscall contenute nel trace file, mantenendo solo quelle presenti nella signature
    trace_sequence = tuple([s for s in trace_sequence if s in set(signature_sequence)])

    result = SignatureMatchResult(mimikatz_module, session_name, trace_filename, signature_sequence)

    if len(signature_sequence) > len(trace_sequence):
        result.outcome = 'Tracefile too short'
        __signature_results[mimikatz_module, session_name, trace_filename] = result
        return result

    length_difference = len(trace_sequence) - len(signature_sequence)
    match_len_at_index = [0] * (length_difference + 1)  # lunghezza match per ciascun offset

    for offset in range(length_difference + 1):

        if strategy == 'strict':

            for i, syscall in enumerate(signature_sequence):
                if syscall != trace_sequence[offset + i]:
                    match_len_at_index[offset] = i + 1
                    break
            else:
                match_len_at_index[offset] = len(signature_sequence)

        elif strategy == 'lax':

            current_syscall_index = 0

            for syscall_in_trace in trace_sequence[offset:]:
                if syscall_in_trace == signature_sequence[current_syscall_index]:
                    current_syscall_index += 1
                    if current_syscall_index == len(signature_sequence):
                        current_syscall_index -= 1
                        break

            match_len_at_index[offset] = current_syscall_index + 1

    result.strategy = strategy
    result.outcome = 'Check performed'
    result.match_lengths = match_len_at_index
    __signature_results[mimikatz_module, session_name, trace_filename, strategy] = result
    return result


def get_syscall_sequences(mimikatz_command, id_range=None, names_only=True):

    sequences = []
    logs_folder = f'input_logs/{mimikatz_command}'

    if id_range is not None:
        first_id, last_id = id_range

    for logfile in [f for f in os.listdir(logs_folder) if f.endswith('.log')]:

        if id_range is not None:

            logfile_no_ext = logfile.split('.')[0]
            log_id = int(logfile_no_ext.split('_')[-1])

            if log_id < first_id or log_id > last_id:
                continue

        current_sequence = parse_syscalls_log(os.path.join(logs_folder, logfile))
        if names_only:
            current_sequence = tuple([entry[0] for entry in current_sequence])  # discard success / failure information

        sequences.append(current_sequence)

    return sequences


def divide_sequences_by_length(sequences):

    by_length = {}  # lenght -> sequences with given lenght

    for sequence in sequences:

        sequence_length = len(sequence)
        if sequence_length not in by_length:
            by_length[sequence_length] = [sequence]
        else:
            by_length[sequence_length].append(sequence)

    return by_length


def plot_sequence_lengths(sequences_by_length, uniques_by_length, mimikatz_module, suffix=None):

    hist_heights = []
    hist_heights_unique = []
    lengths = sorted(sequences_by_length.keys())

    for length in lengths:

        n_sequences = len(sequences_by_length[length])
        hist_heights.append(n_sequences)
        n_uniques = len(uniques_by_length[length])
        hist_heights_unique.append(n_uniques)

    plt.figure()
    plt.bar(lengths, hist_heights)
    plt.bar(lengths, hist_heights_unique)
    plt.title('Length distribution of syscall sequences')
    if suffix is not None:
        plt.suptitle(f'[Module: {mimikatz_module.replace("_", "::")} - Session: {suffix}]')
    else:
        plt.suptitle(f'[Module: {mimikatz_module.replace("_", "::")}]')
    plt.legend(['Total', 'Uniques'])
    plt.xlabel('Sequence length'), plt.ylabel('N. of sequences')

    if suffix is not None:
        plt.savefig(f'results/{mimikatz_module}/plots/sequence_lengths_{suffix}.png')
    else:
        plt.savefig(f'results/{mimikatz_module}/plots/sequence_lengths.png')

    plt.close()


def plot_call_stddevs(all_syscalls, call_stddevs, mimikatz_module, suffix=None):

    plt.figure(figsize=(12, 8), dpi=300)
    plt.title('Std.Dev. of # of invocations for each syscall')
    if suffix is not None:
        plt.suptitle(f'[Module: {mimikatz_module.replace("_", "::")} - Session: {suffix}]')
    else:
        plt.suptitle(f'[Module: {mimikatz_module.replace("_", "::")}]')

    for i in range(len(all_syscalls)):
        container = plt.barh(all_syscalls[i], call_stddevs[i], color='b')
        plt.bar_label(container, padding=1, fontsize=6, color='b' if call_stddevs[i] != 0 else 'r')

    plt.xlabel('Std.Dev.'), plt.yticks(fontsize=6)
    plt.tight_layout()

    if suffix is not None:
        plt.savefig(f'results/{mimikatz_module}/plots/syscall_stddevs_{suffix}.png')
    else:
        plt.savefig(f'results/{mimikatz_module}/plots/syscall_stddevs.png')

    plt.close()


def plot_call_averages(all_syscalls, call_avgs, mimikatz_module, suffix=None):

    plt.figure(figsize=(12, 8), dpi=300)
    plt.title('Average # of invocations for each syscall')
    if suffix is not None:
        plt.suptitle(f'[Module: {mimikatz_module.replace("_", "::")} - Session: {suffix}]')
    else:
        plt.suptitle(f'[Module: {mimikatz_module.replace("_", "::")}]')

    for i in range(len(all_syscalls)):
        container = plt.barh(all_syscalls[i], call_avgs[i], color='b' if call_avgs[i] != 1 else 'r')
        plt.bar_label(container, padding=1, fontsize=6)

    plt.xlabel('Invocations'), plt.yticks(fontsize=6)
    plt.tight_layout()

    if suffix is not None:
        plt.savefig(f'results/{mimikatz_module}/plots/syscall_freqs_{suffix}.png')
    else:
        plt.savefig(f'results/{mimikatz_module}/plots/syscall_freqs.png')

    plt.close()


def prepare_folders(mimikatz_module):

    os.makedirs(f'results/{mimikatz_module}/plots', exist_ok=True)


def analyze_syscall_traces(mimikatz_module, logs_range=None, session_name=None):

    if logs_range is not None:
        if logs_range[0] > logs_range[1]:
            raise ValueError(f'Invalid range: {logs_range}')

    mimikatz_module = mimikatz_module.replace('::', '_')
    prepare_folders(mimikatz_module)

    # Use cached results if available
    global __syscall_results
    try:
        return __syscall_results[mimikatz_module, session_name]
    except KeyError:
        pass

    # No cached results exist for given module and session: generate them
    all_sequences = get_syscall_sequences(mimikatz_module, id_range=logs_range)
    results = analyze_sequences(all_sequences, mimikatz_module, session_name)

    return results


def analyze_sequences(all_sequences, mimikatz_module, session_name, strategy='most_common'):

    all_uniques = tuple(set(all_sequences))

    # Analizziamo le sequenze di syscall, dividendole per lunghezza
    # Vogliamo capire se e quante sequenze UNICHE abbiamo rilevato
    sequences_by_length = divide_sequences_by_length(all_sequences)
    uniques_by_length = divide_sequences_by_length(all_uniques)

    # Plottiamo il numero di sequenze per ciascuna lunghezza
    plot_sequence_lengths(sequences_by_length, uniques_by_length, mimikatz_module, suffix=session_name)

    # Analizziamo ora le singole syscall che vengono effettuate
    # In particolare, vogliamo capire con che frequenza ciascuna syscall compare all'interno delle sequenze
    # Si noti che invocazioni successive della medesima syscall sono considerate come una singola invocazione
    # Ciò è motivato dal fatto che invocazioni successive sono probabilmente mirate ad ottenere complessivamente
    # uno specifico scopo (eg: 10 x NtAllocateVirtualMemory -> tutte mirate ad allocare la memoria necessaria)
    all_syscalls = []
    for seq in all_sequences:
        for syscall in seq:
            if syscall not in all_syscalls:
                all_syscalls.append(syscall)
    all_syscalls = sorted(all_syscalls, reverse=True)

    syscall_freqs = OrderedDict()  # syscall -> frequenza all'interno di ciascuna sequenza
    for syscall in all_syscalls:
        syscall_freqs[syscall] = [0] * len(all_sequences)
    tot_calls = 0
    for i, seq in enumerate(all_sequences):
        tot_calls += len(seq)
        for syscall in seq:
            syscall_freqs[syscall][i] += 1

    # Calcoliamo e plottiamo il numero medio di chiamate di ciascuna syscall nelle varie sequenze rilevate
    call_avgs = [sum(syscall_freqs[s]) / len(all_sequences) for s in all_syscalls]
    plot_call_averages(all_syscalls, call_avgs, mimikatz_module, suffix=session_name)

    # Calcoliamo e plottiamo la deviazione standard del numero di invocazioni per ciascuna syscall tra le sequenze
    call_stddevs = []
    for i, s in enumerate(all_syscalls):
        stddev = math.sqrt(sum([(n - call_avgs[i]) ** 2 for n in syscall_freqs[s]]) / len(all_sequences))
        call_stddevs.append(stddev)

    plot_call_stddevs(all_syscalls, call_stddevs, mimikatz_module, suffix=session_name)

    # Ora che abbiamo osservato come la maggior parte delle syscall sia effettuata un numero preciso - e costante - di
    # volte in ciascuna esecuzione, analizziamo nuovamente le sequenze di syscall eliminando però quelle che variano per
    # numero di chiamate.
    fixed_syscalls = [s for i, s in enumerate(all_syscalls) if call_stddevs[i] == 0]
    filtered_uniques = tuple(set([tuple([s for s in seq if s in fixed_syscalls]) for seq in all_uniques]))

    if strategy == 'most_common':

        # Scegliamo come firma, tra le sequenze filtrate sulle fixed_syscalls, quella più frequente

        if len(filtered_uniques) > 2:

            all_filtered = [[s for s in seq if s in fixed_syscalls] for seq in all_sequences]
            occurrences = [all_filtered.count(s) for s in all_filtered]
            idx_most_common = occurrences.index(max(occurrences))

            signature = filtered_uniques[idx_most_common]

        else:
            signature = filtered_uniques[0]

    else:
        raise ValueError(f'Unknown signature generation strategy: "{strategy}"')

    results = SyscallTracesResult(mimikatz_module, session_name)
    results.syscall_sequences = all_sequences
    results.unique_syscalls = all_syscalls
    results.fixed_syscalls = fixed_syscalls
    results.signature = signature
    results.call_stats = call_avgs, call_stddevs

    global __syscall_results
    __syscall_results[mimikatz_module, session_name] = results

    return results


def aggregate_syscall_traces_analysis(mimikatz_module, session_names, aggregated_session_name):

    mimikatz_module = mimikatz_module.replace('::', '_')

    # Use cached results if available
    global __syscall_results
    try:
        return __syscall_results[mimikatz_module, aggregated_session_name]
    except KeyError:
        pass

    # No cached result exist: generate them
    keys = [(mimikatz_module, session_name) for session_name in session_names]

    all_sequences = []
    for key in keys:
        session_results = __syscall_results[key]
        all_sequences += session_results.syscall_sequences

    return analyze_sequences(all_sequences, mimikatz_module, aggregated_session_name)


def store_cached_results():

    global __syscall_results, __signature_results

    with open(ANALYSIS_RESULTS_FILE, 'wb') as analysis_db:
        pickle.dump(__syscall_results, analysis_db)

    with open(SIGNATURE_MATCH_RESULTS_FILE, 'wb') as match_db:
        pickle.dump(__signature_results, match_db)
