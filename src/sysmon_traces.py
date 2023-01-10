from Evtx import Evtx as evtx
from matplotlib import pyplot as plt
import pickle
import os

from class_definitions import SysmonTracesResults
from class_definitions import LogonPasswordsChecker, LogonPasswordsLeftovers
from class_definitions import DcSyncChecker, DcSyncLeftovers


SYSMON_RESULTS_FILE = 'results/sysmon_traces_results.pkl'


# Cache dei risultati ottenuti dalle analisi
__sysmon_results = {}
if os.path.isfile(SYSMON_RESULTS_FILE):
    with open(SYSMON_RESULTS_FILE, 'rb') as __traces_db:
        __sysmon_results = pickle.load(__traces_db)
        print('[*] Sysmon analysis database was found and loaded')


def get_checker_for_module(mimikatz_module):

    if mimikatz_module == 'sekurlsa_logonpasswords':
        return LogonPasswordsChecker()
    elif mimikatz_module == 'lsadump_dcsync':
        return DcSyncChecker()
    else:
        raise ValueError(f'No checker available for module: {mimikatz_module}')


def get_leftovers_register_for_module(mimikatz_module):

    if mimikatz_module == 'sekurlsa_logonpasswords':
        return LogonPasswordsLeftovers()
    elif mimikatz_module == 'lsadump_dcsync':
        return DcSyncLeftovers()
    else:
        raise ValueError(f'No leftovers register available for module: {mimikatz_module}')


def plot_sysmon_logs_info(n_records, noise_entries, leftovers, n_runs, mimikatz_module, suffix=None):

    plt.figure(figsize=(15, 8), dpi=300)
    if suffix is not None:
        plt.suptitle(f'[Module: {mimikatz_module.replace("_", "::")} - Session: {suffix}]')
    else:
        plt.suptitle(f'[Module: {mimikatz_module.replace("_", "::")}]')

    plt.subplot(121)
    plt.title(f'# of detections per IoC out of {n_runs} runs')
    iocs = list(leftovers.keys())
    detections = [n_runs - leftovers[ioc] for ioc in iocs]
    container = plt.barh(iocs, detections, height=0.4)
    for i in range(len(iocs)):
        plt.bar_label(container, padding=2, fontsize=10)
    plt.ylabel('Indicators of Compromise'), plt.xlabel('# of detections')

    plt.subplot(122)
    plt.title(f'# of noise entries out of {n_records} total log records')
    container = plt.bar('Total noise', noise_entries, width=0.4)
    plt.bar_label(container)

    if mimikatz_module == 'sekurlsa_logonpasswords':
        adj_noise = noise_entries - (3 + 3 * n_runs)
    elif mimikatz_module == 'lsadump_dcsync':
        adj_noise = noise_entries - n_runs
    else:
        adj_noise = noise_entries

    container = plt.bar('Adjusted noise', adj_noise, width=0.4)
    plt.bar_label(container)
    plt.ylabel('# entries')

    plt.tight_layout()

    if suffix is not None:
        plt.savefig(f'results/{mimikatz_module}/plots/sysmon_iocs_{suffix}.png')
    else:
        plt.savefig(f'results/{mimikatz_module}/plots/sysmon_iocs.png')

    plt.close()


def analyze_sysmon_traces(mimikatz_module, n_runs, session_name):
    """
    Verifica la qualità degli IoC attesi all'interno dei file di registro degli eventi di Windows

    :param mimikatz_module: Il nome del modulo di Mimikatz per cui si vuole effettuare il controllo
    :param session_name: Stringa identificativa della sessione di test per cui si vogliono controllare i log
    :param n_runs: Numero di esecuzioni di Mimikatz effettuate nella sessione di test sotto esame
    :return:
    """

    mimikatz_module = mimikatz_module.replace('::', "_")

    # Use cached results if available
    global __sysmon_results
    try:
        return __sysmon_results[mimikatz_module, session_name]
    except KeyError:
        pass

    leftovers_register = get_leftovers_register_for_module(mimikatz_module)
    n_records = 0
    ok_runs = 0
    noise_entries = 0
    current_checker = None

    with evtx.Evtx(f'sysmon_logs/{mimikatz_module}_{session_name}.evtx') as evt_log:

        # Ogni record è un evento nel file di log
        for record in evt_log.records():

            n_records += 1

            record_xml_tree = record.lxml()

            # Cerchiamo innanzitutto EventID = 1 (ProcessCreation)
            # -> questo perchè cosí possiamo distinguere i record legati alla stessa esecuzione

            # Per la motivazione dietro a ns_prefix map, see:
            # https://stackoverflow.com/questions/37586536/lxml-doc-find-returning-none
            ns_prefix_map = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            evt_id = int(record_xml_tree.find('.//ns:EventID', ns_prefix_map).text)

            if evt_id == 1:  # ProcessCreation
                current_checker = get_checker_for_module(mimikatz_module)

            # Gestiamo il caso dei log precedenti alla prima esecuzione di Mimikatz
            elif current_checker is None:
                noise_entries += 1

            elif evt_id == 5:  # ProcessTermination
                if current_checker.give_response():
                    ok_runs += 1
                else:
                    leftovers_register.register(current_checker.get_leftovers())
                noise_entries += current_checker.get_observed_noise()
                current_checker = None

            else:
                current_checker.process(record_xml_tree, evt_id)

    leftovers = leftovers_register.as_dict()

    plot_sysmon_logs_info(n_records, noise_entries, leftovers, n_runs, mimikatz_module, session_name)

    results = SysmonTracesResults(mimikatz_module)
    results.session_name = session_name
    results.leftovers = leftovers
    results.n_log_records = n_records
    results.noise = noise_entries
    results.n_runs = n_runs

    __sysmon_results[mimikatz_module, session_name] = results

    return results


def aggregate_sysmon_traces_analysis(mimikatz_module, session_names, aggregated_session_name):

    mimikatz_module = mimikatz_module.replace('::', '_')

    # Use cached results if available
    global __sysmon_results
    try:
        return __sysmon_results[mimikatz_module, aggregated_session_name]
    except KeyError:
        pass

    keys = [(mimikatz_module, session_name) for session_name in session_names]

    aggregated_results = SysmonTracesResults(mimikatz_module)
    aggregated_results.session_name = aggregated_session_name
    aggregated_results.leftovers = get_leftovers_register_for_module(mimikatz_module).as_dict()
    aggregated_results.n_runs = 0
    aggregated_results.n_log_records = 0
    aggregated_results.noise = 0

    for key in keys:

        session_results = __sysmon_results[key]

        for leftovers_key in aggregated_results.leftovers.keys():
            aggregated_results.leftovers[leftovers_key] += session_results.leftovers[leftovers_key]
        aggregated_results.n_runs += session_results.n_runs
        aggregated_results.n_log_records += session_results.n_log_records
        aggregated_results.noise = session_results.noise[0] + aggregated_results.noise[0]

    plot_sysmon_logs_info(
        aggregated_results.n_log_records,
        aggregated_results.noise[0],
        aggregated_results.leftovers,
        aggregated_results.n_runs,
        mimikatz_module,
        aggregated_session_name)

    __sysmon_results[mimikatz_module, aggregated_session_name] = aggregated_results

    return aggregated_results


def store_cached_results():

    global __sysmon_results

    with open(SYSMON_RESULTS_FILE, 'wb') as traces_db:
        pickle.dump(__sysmon_results, traces_db)
