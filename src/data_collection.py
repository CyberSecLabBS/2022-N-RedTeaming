import subprocess
import datetime
import os
import os.path
import sys


def run_and_trace(mimikatz_cmd, n_runs=100, needs_debug=True):

    short_cmd_name = mimikatz_cmd.strip("'").split(" ")[0].replace("::", "_")

    logs_folder = rf'\\vmware-host\Shared Folders\input_logs\{short_cmd_name}'
    escaped_logs_folder = rf'\\vmware-host\Shared` Folders\input_logs\{short_cmd_name}'
    mimikatz_binary = r'C:\Users\nudls\Desktop\mimikatz_bin\mimikatz64.exe'
    debug_priv = 'privilege::debug' if needs_debug else ''
    cmdline = fr'powershell -Command "drstrace -logdir {escaped_logs_folder} -- {mimikatz_binary} {debug_priv} {mimikatz_cmd} exit"'

    started_time = datetime.datetime.now()

    for i in range(n_runs):

        print(f' ---------- Run #{i} ----------')
        print(f'[cmdline]: {cmdline}')

        # Run Mimikatz with supplied command
        proc = subprocess.run(cmdline, capture_output=True)
        print('[stderr]:\n')
        print(proc.stderr.decode('utf-8'))
        print('[stdout]:\n')
        print(proc.stdout.decode('utf-8'))

        # Identify trace log for this execution and rename it according to our convention
        generated_prefix = 'drstrace.mimikatz64.exe'
        custom_prefix = f'{short_cmd_name}_'

        all_logs = os.listdir(logs_folder)
        candidates = [f for f in all_logs if f.startswith(generated_prefix)]

        if len(candidates) > 1:
            print('[ERROR] Found more than one yet-to-be-renamed logfile:')
            print(candidates)
            sys.exit()
        elif len(candidates) == 0:
            print('[ERROR] No logfile was found')
            sys.exit()

        logfile = candidates[0]

        # Now that we got the logfile we need to rename, check if any previous log for the current command exist
        candidates = [f for f in all_logs if f.startswith(custom_prefix)]

        if len(candidates) == 0:
            logs_counter = 1
        else:
            logs_counter = max([int(i.removeprefix(custom_prefix).removesuffix('.log')) for i in candidates]) + 1

        # Actually rename the file
        os.rename(f'{logs_folder}\\{logfile}', f'{logs_folder}\\{custom_prefix}{logs_counter}.log')

        print('\n')

    print(f'[STARTED]: {started_time}')
    print(f'[TERMINATED]: {datetime.datetime.now()}')


if __name__ == '__main__':

    run_and_trace("sekurlsa::logonpasswords", 100)

    # Per invocare comandi che necessitano di parametri è necessario racchiudere il comando tra singoli apici
    run_and_trace("'lsadump::dcsync /all'", 150, needs_debug=False)
