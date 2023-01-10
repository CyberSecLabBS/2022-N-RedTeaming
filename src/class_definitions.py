class SyscallTracesResult:

    def __init__(self, mimikatz_module, session_name):
        self._module = mimikatz_module.replace('_', '::')
        self._session_name = session_name
        self._syscall_sequences = None
        self._signature_sequence = None
        self._unique_syscalls = None
        self._fixed_syscalls = None
        self._call_stats = None  # tuple: (call_averages:float[], call_stddevs:float[])

    @property
    def session_name(self):
        return self._session_name

    @property
    def syscall_sequences(self):
        return self._syscall_sequences

    @syscall_sequences.setter
    def syscall_sequences(self, sequences):
        self._syscall_sequences = sequences

    @property
    def signature(self):
        return self._signature_sequence

    @signature.setter
    def signature(self, sequence):
        self._signature_sequence = sequence

    @property
    def unique_syscalls(self):
        return self._unique_syscalls

    @unique_syscalls.setter
    def unique_syscalls(self, syscalls):
        self._unique_syscalls = syscalls

    @property
    def fixed_syscalls(self):
        return self._fixed_syscalls

    @fixed_syscalls.setter
    def fixed_syscalls(self, syscalls):
        self._fixed_syscalls = syscalls

    @property
    def call_stats(self):
        return self._call_stats

    @call_stats.setter
    def call_stats(self, stats):
        self._call_stats = stats


class SignatureMatchResult:

    def __init__(self, mimikatz_module, session_name, tracefile, signature):

        self._module = mimikatz_module.replace("_", "::")
        self._session_name = session_name
        self._tracefile = tracefile
        self._signature_len = len(signature)
        self._match_len_per_index = None  # list: offset -> match length
        self._outcome = None
        self._strategy = None
        self._best_match_len = 0

    def __str__(self):

        lines = [
            '',
            f'[Tracefile]\t{self._tracefile}',
            f'[Signature]\t{self._module}::{self._session_name}',
            f'[Outcome]\t{self._outcome}'
        ]

        if self._outcome.startswith('Check performed'):
            lines += [
                f' -> [Strategy]\t{self.strategy}',
                f' -> [Match %]\t{self.match_score:.2f} %',
                f' -> [Match #]\t{self._best_match_len} / {self._signature_len}'
            ]

        return '\n'.join(lines)

    @property
    def match_score(self):
        return (self._best_match_len / self._signature_len) * 100

    @property
    def strategy(self):
        return self._strategy

    @strategy.setter
    def strategy(self, strategy):
        self._strategy = strategy

    @property
    def outcome(self):
        return self._outcome

    @outcome.setter
    def outcome(self, outcome: str):
        self._outcome = outcome

    @property
    def match_lengths(self):
        return self._match_len_per_index

    @match_lengths.setter
    def match_lengths(self, match_len_per_index):
        self._match_len_per_index = match_len_per_index
        self._best_match_len = max(match_len_per_index)


class LogonPasswordsChecker:

    def __init__(self):
        self._dll_loadings = [
            'ntdsapi.dll',
            'netapi32.dll',
            'imm32.dll',
            'samlib.dll',
            'combase.dll',
            'srvcli.dll',
            'shcore.dll',
            'ntasn1.dll',
            'cryptdll.dll',
            'logoncli.dll'
        ]
        self._lsass_accessed = False
        self._num_noise_events = 0

    def process(self, lxml_record_tree, event_id):

        # First, we check that the event corresponds to a Mimikatz execution

        # Per la motivazione dietro a prefix map, see:
        # https://stackoverflow.com/questions/37586536/lxml-doc-find-returning-none
        prefix_map = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        image_element = lxml_record_tree.find('.//ns:Data[@Name="Image"]', prefix_map)
        if image_element is not None:
            executable_name = image_element.text.lower()
        else:
            executable_name = lxml_record_tree.find('.//ns:Data[@Name="SourceImage"]', prefix_map).text.lower()

        if "mimikatz" not in executable_name:
            self._num_noise_events += 1
            return

        # L'evento in questione e' stato generato da Mimikatz: processiamolo
        if event_id == 7:  # ImageLoaded
            loaded_dll = lxml_record_tree.find('.//ns:Data[@Name="ImageLoaded"]', prefix_map).text.lower()
            for i, dll in enumerate(self._dll_loadings):
                if dll in loaded_dll:
                    del self._dll_loadings[i]
                    break
            else:
                self._num_noise_events += 1

        elif event_id == 10:  # ProcessAccess
            accessed_process = lxml_record_tree.find('.//ns:Data[@Name="TargetImage"]', prefix_map)
            if 'lsass.exe' in accessed_process:
                self._lsass_accessed = True
            else:
                self._num_noise_events += 1

        else:
            self._num_noise_events += 1

    def give_response(self):
        return len(self._dll_loadings) == 0 and self._lsass_accessed

    def get_leftovers(self):
        return self._dll_loadings, self._lsass_accessed

    def get_observed_noise(self):
        return self._num_noise_events


class LogonPasswordsLeftovers:

    def __init__(self):

        self._dlls = {
            'ntdsapi.dll': 0,
            'netapi32.dll': 0,
            'imm32.dll': 0,
            'samlib.dll': 0,
            'combase.dll': 0,
            'srvcli.dll': 0,
            'shcore.dll': 0,
            'ntasn1.dll': 0,
            'cryptdll.dll': 0,
            'logoncli.dll': 0
        }
        self._lsass_accesses = 0

    def __str__(self):

        str_repr = ''
        for dll, n in sorted(self._dlls.items()):
            str_repr += f'{dll}: {n}\n'
        str_repr += f'lsass access: {self._lsass_accesses}'

        return str_repr

    def register(self, leftovers):

        leftover_dlls, leftover_access = leftovers

        for dll in leftover_dlls:
            self._dlls[dll] += 1

        if leftover_access:
            self._lsass_accesses += 1

    def as_dict(self):

        leftovers = dict(self._dlls)
        leftovers['LSASS access'] = self._lsass_accesses

        return leftovers


class DcSyncChecker:

    def __init__(self):
        self._num_detections = 0
        self._num_noise_events = 0

    def process(self, lxml_record_tree, event_id):

        if event_id != 4662:
            self._num_noise_events += 1
            return

        # Per la motivazione dietro a prefix map, see:
        # https://stackoverflow.com/questions/37586536/lxml-doc-find-returning-none
        prefix_map = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        # Controlliamo che SubjectUserName non sia un acount macchina
        subject_user_name_element = lxml_record_tree.find('.//ns:Data[@Name="SubjectUserName"]', prefix_map)
        if subject_user_name_element.text.endswith('$'):
            self._num_noise_events += 1
            return

        # Controlliamo che l'access mask sia 0x100
        access_mask_element = lxml_record_tree.find('.//ns:Data[@Name="AccessMask"]', prefix_map)
        if int(access_mask_element.text, 16) != 0x100:
            self._num_noise_events += 1
            return

        # Controlliamo che il campo Properties contenga il contenuto di nostro interesse
        ioc_values = [
            '{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}',
            '{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}',
            '{9923a32a-3607-11d2-b9be-0000f87a36b2}',
            'Replicating Directory Changes all'
        ]
        properties_element = lxml_record_tree.find('.//ns:Data[@Name="Properties"]', prefix_map)

        if "%%7688" not in properties_element.text:
            self._num_noise_events += 1
            return

        for value in ioc_values:
            if value in properties_element.text:
                break
        else:
            self._num_noise_events += 1
            return

        # Tutti i controlli sono andati a buon fine: abbiamo trovato una entry valida per l'IoC
        self._num_detections += 1

    def give_response(self):
        return self._num_detections > 0

    def get_leftovers(self):
        return 1 if self._num_detections == 0 else 0

    def get_observed_noise(self):
        return self._num_noise_events


class DcSyncLeftovers:

    def __init__(self):
        self._detected = False

    def __str__(self):
        if self._detected:
            return 'Event 4662 was detected'
        else:
            return 'Event 4662 was NOT detected'

    def register(self, leftovers):
        if leftovers == 0:
            self._detected = True

    def as_dict(self):
        return {'Event 4662': 1 if not self._detected else 0}


class SysmonTracesResults:

    def __init__(self, mimikatz_module):
        self._module = mimikatz_module.replace('_', '::')
        self._leftovers = None
        self._n_log_records = None
        self._n_noise_entries = None
        self._session_name = None
        self._n_runs = None

    @property
    def session_name(self):
        return self._session_name

    @session_name.setter
    def session_name(self, name):
        self._session_name = name

    @property
    def leftovers(self):
        return self._leftovers

    @leftovers.setter
    def leftovers(self, leftovers):
        self._leftovers = leftovers

    @property
    def n_runs(self):
        return self._n_runs

    @n_runs.setter
    def n_runs(self, n_runs):
        self._n_runs = n_runs

    @property
    def n_log_records(self):
        return self._n_log_records

    @n_log_records.setter
    def n_log_records(self, n_records):
        self._n_log_records = n_records

    @property
    def noise(self):

        tot_noise = self._n_noise_entries
        if self._module == 'sekurlsa::logonpasswords':
            adj_noise = tot_noise - (3 + 3 * self._n_runs)
        elif self._module == 'lsadump::dcsync':
            adj_noise = tot_noise - self._n_runs
        else:
            raise ValueError(f'Unknown module: {self._module}')

        return tot_noise, adj_noise

    @noise.setter
    def noise(self, noise_entries):
        self._n_noise_entries = noise_entries
