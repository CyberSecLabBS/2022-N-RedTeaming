import os

from syscall_traces import analyze_syscall_traces, aggregate_syscall_traces_analysis, check_signature_in_tracefile
from syscall_traces import store_cached_results as store_syscall_results
from sysmon_traces import analyze_sysmon_traces, aggregate_sysmon_traces_analysis
from sysmon_traces import store_cached_results as store_sysmon_results


def benchmark_signature(mimikatz_module, session_name):

    mimikatz_module = mimikatz_module.replace("::", "_")

    for file in [f'input_logs/benchmark/{f}' for f in os.listdir('input_logs/benchmark') if f.endswith('.log')]:
        result = check_signature_in_tracefile(mimikatz_module, session_name, file, strategy='strict')
        print(result)
        result = check_signature_in_tracefile(mimikatz_module, session_name, file, strategy='lax')
        print(result)


def store_cached_results():

    store_syscall_results()
    store_sysmon_results()


def sekurlsa_logonpasswords():

    print('### Starting analysis of module sekurlsa::logonpasswords ###')

    # Sessioni con clear-text credentials disabilitate

    analyze_syscall_traces('sekurlsa::logonpasswords', logs_range=(101, 200), session_name='1')
    analyze_syscall_traces('sekurlsa::logonpasswords', logs_range=(501, 600), session_name='5')
    analyze_syscall_traces('sekurlsa::logonpasswords', logs_range=(601, 700), session_name='6')

    analyze_sysmon_traces('sekurlsa::logonpasswords', n_runs=100, session_name='1')
    analyze_sysmon_traces('sekurlsa::logonpasswords', n_runs=100, session_name='5')
    analyze_sysmon_traces('sekurlsa::logonpasswords', n_runs=100, session_name='6')

    # Sessioni con clear-text credentials abilitate

    analyze_syscall_traces('sekurlsa::logonpasswords', logs_range=(201, 300), session_name='2')
    analyze_syscall_traces('sekurlsa::logonpasswords', logs_range=(301, 400), session_name='3')
    analyze_syscall_traces('sekurlsa::logonpasswords', logs_range=(401, 500), session_name='4')

    analyze_sysmon_traces('sekurlsa::logonpasswords', n_runs=100, session_name='2')
    analyze_sysmon_traces('sekurlsa::logonpasswords', n_runs=100, session_name='3')
    analyze_sysmon_traces('sekurlsa::logonpasswords', n_runs=100, session_name='4')

    # Sessioni ottenute aggregando i risultati delle sessioni singole

    aggregate_sysmon_traces_analysis('sekurlsa::logonpasswords', ['1', '5', '6'], 'no_cleartext')
    aggregate_sysmon_traces_analysis('sekurlsa::logonpasswords', ['2', '3', '4'], 'cleartext')
    aggregate_sysmon_traces_analysis('sekurlsa::logonpasswords', ['1', '2', '3', '4', '5', '6'], 'all')

    aggregate_syscall_traces_analysis('sekurlsa::logonpasswords', ['1', '5', '6'], 'no_cleartext')
    aggregate_syscall_traces_analysis('sekurlsa::logonpasswords', ['2', '3', '4'], 'cleartext')
    aggregate_syscall_traces_analysis('sekurlsa::logonpasswords', ['1', '2', '3', '4', '5', '6'], 'all')

    # Benchmark delle signature ottenute
    benchmark_signature('sekurlsa::logonpasswords', '1')
    benchmark_signature('sekurlsa::logonpasswords', '2')
    benchmark_signature('sekurlsa::logonpasswords', '3')
    benchmark_signature('sekurlsa::logonpasswords', '4')
    benchmark_signature('sekurlsa::logonpasswords', '5')
    benchmark_signature('sekurlsa::logonpasswords', '6')
    benchmark_signature('sekurlsa::logonpasswords', 'cleartext')
    benchmark_signature('sekurlsa::logonpasswords', 'no_cleartext')
    benchmark_signature('sekurlsa::logonpasswords', 'all')

    print()


def lsadump_dcsync():

    print('### Starting analysis of module lsadump::dcsync ###')

    # Sessione con flag /all
    analyze_syscall_traces('lsadump::dcsync', logs_range=(1, 150), session_name='1')
    analyze_sysmon_traces('lsadump::dcsync', n_runs=150, session_name='1')

    # Sessione con flag /user:krbtgt
    analyze_syscall_traces('lsadump::dcsync', logs_range=(151, 300), session_name='2')
    analyze_sysmon_traces('lsadump::dcsync', n_runs=150, session_name='2')

    # Sessione aggregata
    aggregate_syscall_traces_analysis('lsadump::dcsync', ['1', '2'], 'all')
    aggregate_sysmon_traces_analysis('lsadump::dcsync', ['1', '2'], 'all')

    # Benchmark delle signature ottenute
    benchmark_signature('lsadump::dcsync', '1')
    benchmark_signature('lsadump::dcsync', '2')
    benchmark_signature('lsadump::dcsync', 'all')


def token_elevate():

    print('### Starting analysis of module token::elevate ###')

    # Sessione senza flag -> impersonate SYSTEM
    analyze_syscall_traces('token::elevate', logs_range=(1, 50), session_name='system')

    # Sessione con flag /domainadmin
    analyze_syscall_traces('token::elevate', logs_range=(51, 100), session_name='domainadmin')

    # Sessione aggregata
    aggregate_syscall_traces_analysis('token::elevate', ['system', 'domainadmin'], 'all')

    # Benchmark delle signature ottenute
    benchmark_signature('token::elevate', 'system')
    benchmark_signature('token::elevate', 'domainadmin')
    benchmark_signature('token::elevate', 'all')


if __name__ == '__main__':

    sekurlsa_logonpasswords()
    lsadump_dcsync()
    token_elevate()

    store_cached_results()
