import {
  ChangeDetectorRef,
  Component,
  ElementRef,
  HostListener,
  OnInit,
  ViewChild,
  inject,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { FEATURES, Feature, SAMPLE_PRESETS } from './feature-schema';
import {
  FEATURE_GROUPS,
  FEATURE_METADATA,
  FeatureGroup,
  FeatureMeta,
} from './feature-metadata';
import { PredictionResponse, PredictionService } from './prediction.service';

export interface ClassProbBar {
  name: string;
  prob: number;
  percent: string;
}

export interface ModelBenchmark {
  name: string;
  shortName: string;
  family: string;
  accuracyNum: number;
  accuracy: string;
  macroF1Num: number;
  macroF1: string;
  rocAucNum: number;
  rocAuc: string;
  prAucNum: number;
  prAuc: string;
  overfitGapNum: number;
  overfitGap: string;
  latencyNum: number;
  latency: string;
  trainTime: string;
  best?: boolean;
}

export type BenchmarkMetricKey =
  | 'accuracy'
  | 'macroF1'
  | 'rocAuc'
  | 'prAuc'
  | 'overfitGap'
  | 'latency';

export interface ClassificationLogEntry {
  id: number;
  timestamp: string;
  sourceLabel: string;
  modifiedCount: number;
  prediction: string;
  isNormal: boolean;
  confidence: string;
  latencyMs: number | null;
  mode: 'Live API' | 'Static Replay';
  snapshot: Record<string, string | number>;
  response: PredictionResponse;
}

const STATIC_PRESET_RESULTS: Record<string, PredictionResponse> = {
  Normal: {
    prediction: 'Normal',
    predicted_class_index: 7,
    task: 'classification',
    probabilities: [0.000001, 0.000003, 0, 0.000001, 0, 0, 0, 0.999988, 0.000001, 0, 0.000001, 0, 0.000001, 0.000002, 0.000001],
    class_probabilities: {
      Normal: 0.999988, DDoS_HTTP: 0.000003, Vulnerability_scanner: 0.000002,
      Backdoor: 0.000001, DDoS_TCP: 0.000001, Password: 0.000001, Ransomware: 0.000001, Uploading: 0.000001, XSS: 0.000001,
      DDoS_ICMP: 0, DDoS_UDP: 0, Fingerprinting: 0, MITM: 0, Port_Scanning: 0, SQL_injection: 0
    },
    disclaimer: 'Research prototype evaluated on Edge-IIoTset (Static Replay Mode).'
  },
  DDoS_TCP: {
    prediction: 'DDoS_TCP',
    predicted_class_index: 3,
    task: 'classification',
    probabilities: [0, 0.000055, 0, 0.999889, 0, 0, 0, 0.000001, 0.000017, 0, 0, 0.000029, 0.000001, 0.000001, 0.000005],
    class_probabilities: {
      DDoS_TCP: 0.999889, DDoS_HTTP: 0.000055, SQL_injection: 0.000029, Password: 0.000017, XSS: 0.000005,
      Normal: 0.000001, Uploading: 0.000001, Vulnerability_scanner: 0.000001,
      Backdoor: 0, DDoS_ICMP: 0, DDoS_UDP: 0, Fingerprinting: 0, MITM: 0, Port_Scanning: 0, Ransomware: 0
    },
    disclaimer: 'Research prototype evaluated on Edge-IIoTset (Static Replay Mode).'
  },
  SQL_injection: {
    prediction: 'SQL_injection',
    predicted_class_index: 11,
    task: 'classification',
    probabilities: [0.000006, 0.000804, 0.000006, 0.000006, 0.000007, 0.000002, 0.000003, 0.00001, 0.000372, 0.000005, 0.000006, 0.998582, 0.000103, 0.000028, 0.00006],
    class_probabilities: {
      SQL_injection: 0.998582, DDoS_HTTP: 0.000804, Password: 0.000372, Uploading: 0.000103, XSS: 0.00006,
      Vulnerability_scanner: 0.000028, Normal: 0.00001, DDoS_UDP: 0.000007, Backdoor: 0.000006, DDoS_ICMP: 0.000006,
      DDoS_TCP: 0.000006, Ransomware: 0.000006, Port_Scanning: 0.000005, MITM: 0.000003, Fingerprinting: 0.000002
    },
    disclaimer: 'Research prototype evaluated on Edge-IIoTset (Static Replay Mode).'
  },
  Ransomware: {
    prediction: 'Ransomware',
    predicted_class_index: 10,
    task: 'classification',
    probabilities: [0.000019, 0.000006, 0, 0, 0, 0, 0, 0.000003, 0.000001, 0, 0.999947, 0.000003, 0.000012, 0.000004, 0.000003],
    class_probabilities: {
      Ransomware: 0.999947, Backdoor: 0.000019, Uploading: 0.000012, DDoS_HTTP: 0.000006, Vulnerability_scanner: 0.000004,
      Normal: 0.000003, SQL_injection: 0.000003, XSS: 0.000003, Password: 0.000001,
      DDoS_ICMP: 0, DDoS_TCP: 0, DDoS_UDP: 0, Fingerprinting: 0, MITM: 0, Port_Scanning: 0
    },
    disclaimer: 'Research prototype evaluated on Edge-IIoTset (Static Replay Mode).'
  }
};

const PRESET_PROTOS: Record<string, { label: string; proto: string }> = {
  Normal: { label: 'Normal Telemetry', proto: 'MQTT :1883' },
  DDoS_TCP: { label: 'DDoS TCP Flood', proto: 'TCP :80' },
  SQL_injection: { label: 'SQL Injection', proto: 'HTTP :80' },
  Ransomware: { label: 'Ransomware C2', proto: 'C2 :4321' },
};

const CLASS_DESCRIPTIONS: Record<string, { category: string; explanation: string; action: string }> = {
  Normal: {
    category: 'Benign IIoT Telemetry',
    explanation: 'MQTT/TCP telemetry on port 1883 with clean state transitions and no injection or C2 indicators.',
    action: 'Permit flow; no policy intervention needed.'
  },
  DDoS_TCP: {
    category: 'Volumetric Transport Flood',
    explanation: 'High-rate TCP control traffic targeting port 80 with RST/ACK anomalies, empty payload, and wide ephemeral port spread.',
    action: 'Rate-limit source subnet at edge gateway and enforce SYN cookies.'
  },
  SQL_injection: {
    category: 'Application-Layer Injection',
    explanation: 'HTTP request carrying SQL syntax patterns (psfe_app_sqli_flag=1) with elevated URI query length and payload entropy.',
    action: 'Block HTTP request at WAF layer and revoke active session token.'
  },
  Ransomware: {
    category: 'Malware Command & Control',
    explanation: 'Encrypted TCP payload on non-standard service port (4321) with elevated Shannon entropy and TCP timestamp options.',
    action: 'Isolate source IIoT endpoint and block outbound C2 destination.'
  }
};

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App implements OnInit {
  @ViewChild('searchInput') searchInputRef?: ElementRef<HTMLInputElement>;

  readonly fields = FEATURES;
  readonly featureGroups = FEATURE_GROUPS;
  readonly metaByName = FEATURE_METADATA;
  readonly presets = SAMPLE_PRESETS;
  readonly presetNames = Object.keys(SAMPLE_PRESETS);
  readonly deployedStatic =
    typeof window !== 'undefined' &&
    !['localhost', '127.0.0.1', ''].includes(window.location.hostname);

  readonly benchmarks: ModelBenchmark[] = [
    {
      name: 'XGBoost + PP-PSFE',
      shortName: 'XGBoost + PP-PSFE',
      family: 'Gradient Boosted Trees (Selected)',
      accuracyNum: 96.49,
      accuracy: '96.49%',
      macroF1Num: 0.9618,
      macroF1: '0.9618',
      rocAucNum: 0.9991,
      rocAuc: '0.9991',
      prAucNum: 0.9874,
      prAuc: '0.9874',
      overfitGapNum: 0.0057,
      overfitGap: '+0.0057',
      latencyNum: 3.54,
      latency: '3.54 ms',
      trainTime: '13.93 s',
      best: true,
    },
    {
      name: 'LightGBM',
      shortName: 'LightGBM',
      family: 'Leaf-Wise GBDT',
      accuracyNum: 96.33,
      accuracy: '96.33%',
      macroF1Num: 0.9596,
      macroF1: '0.9596',
      rocAucNum: 0.9991,
      rocAuc: '0.9991',
      prAucNum: 0.9888,
      prAuc: '0.9888',
      overfitGapNum: 0.0210,
      overfitGap: '+0.0210',
      latencyNum: 18.35,
      latency: '18.35 ms',
      trainTime: '7.61 s',
    },
    {
      name: 'Random Forest',
      shortName: 'Random Forest',
      family: 'Bagging Ensemble',
      accuracyNum: 94.38,
      accuracy: '94.38%',
      macroF1Num: 0.9414,
      macroF1: '0.9414',
      rocAucNum: 0.9978,
      rocAuc: '0.9978',
      prAucNum: 0.9768,
      prAuc: '0.9768',
      overfitGapNum: 0.0020,
      overfitGap: '+0.0020',
      latencyNum: 10.35,
      latency: '10.35 ms',
      trainTime: '3.46 s',
    },
    {
      name: 'Logistic Regression',
      shortName: 'Logistic Regression',
      family: 'Linear Baseline',
      accuracyNum: 84.87,
      accuracy: '84.87%',
      macroF1Num: 0.8419,
      macroF1: '0.8419',
      rocAucNum: 0.9829,
      rocAuc: '0.9829',
      prAucNum: 0.8656,
      prAuc: '0.8656',
      overfitGapNum: 0.0016,
      overfitGap: '+0.0016',
      latencyNum: 0.43,
      latency: '0.43 ms',
      trainTime: '23.18 s',
    },
  ];

  readonly benchmarkMetrics: {
    key: BenchmarkMetricKey;
    label: string;
    direction: string;
  }[] = [
    { key: 'accuracy', label: 'Test Accuracy', direction: 'Higher is better' },
    { key: 'macroF1', label: 'Macro F1', direction: 'Higher is better' },
    { key: 'rocAuc', label: 'ROC-AUC', direction: 'Higher is better' },
    { key: 'prAuc', label: 'PR-AUC', direction: 'Higher is better' },
    { key: 'overfitGap', label: 'Overfit Gap', direction: 'Lower is better' },
    { key: 'latency', label: 'Latency / 1k', direction: 'Lower is better' },
  ];

  activeTab: 'classifier' | 'benchmarks' | 'history' = 'classifier';
  theme: 'dark' | 'light' = 'dark';
  apiState: 'checking' | 'online' | 'offline' | 'static' = 'checking';
  apiLatencyMs: number | null = null;

  activePreset = 'Normal';
  autoClassify = true;
  values: Record<string, string | number | null> = {};
  baselineValues: Record<string, string | number | null> = {};
  lastClassifiedSignature = '';

  selectedGroup: 'all' | FeatureGroup = 'all';
  searchQuery = '';
  onlyNonZero = false;
  onlyModified = false;

  loading = false;
  error = '';
  result: PredictionResponse | null = null;
  lastLatencyMs: number | null = null;
  allProbabilities: ClassProbBar[] = [];
  showAllClasses = false;

  selectedMetric: BenchmarkMetricKey = 'accuracy';
  history: ClassificationLogEntry[] = [];
  private nextLogId = 1;

  jsonModalOpen = false;
  jsonDraft = '';
  jsonError = '';
  jsonCopied = false;

  private api = inject(PredictionService);
  private cdr = inject(ChangeDetectorRef);

  ngOnInit() {
    this.initTheme();
    this.checkHealth();
    this.loadPreset('Normal', true);
  }

  @HostListener('window:keydown', ['$event'])
  handleKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape' && this.jsonModalOpen) {
      this.closeJsonModal();
      return;
    }

    const target = event.target as HTMLElement | null;
    const isEditingText =
      target?.tagName === 'INPUT' ||
      target?.tagName === 'TEXTAREA' ||
      target?.tagName === 'SELECT';

    if (event.key === '/' && !isEditingText && this.activeTab === 'classifier') {
      event.preventDefault();
      this.searchInputRef?.nativeElement.focus();
      return;
    }

    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter' && this.activeTab === 'classifier') {
      event.preventDefault();
      if (!this.loading) {
        this.submit();
      }
    }
  }

  private initTheme() {
    if (typeof window === 'undefined') return;
    try {
      const saved = window.localStorage?.getItem('edge-ids-theme');
      this.theme = saved === 'light' ? 'light' : 'dark';
    } catch {
      this.theme = 'dark';
    }
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', this.theme);
    }
  }

  toggleTheme() {
    this.theme = this.theme === 'dark' ? 'light' : 'dark';
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', this.theme);
    }
    if (typeof window !== 'undefined') {
      try {
        window.localStorage?.setItem('edge-ids-theme', this.theme);
      } catch {
        // Ignore storage errors in restricted contexts.
      }
    }
  }

  checkHealth() {
    if (this.deployedStatic) {
      this.apiState = 'static';
      this.apiLatencyMs = null;
      return;
    }
    this.apiState = 'checking';
    const started = typeof performance !== 'undefined' ? performance.now() : Date.now();
    this.api.health().subscribe({
      next: res => {
        const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
        this.apiState = res.status === 'ok' ? 'online' : 'offline';
        this.apiLatencyMs = Math.max(1, Math.round(now - started));
        this.cdr.markForCheck();
      },
      error: () => {
        this.apiState = 'offline';
        this.apiLatencyMs = null;
        this.cdr.markForCheck();
      },
    });
  }

  presetLabel(name: string): string {
    return PRESET_PROTOS[name]?.label ?? name;
  }

  presetProto(name: string): string {
    return PRESET_PROTOS[name]?.proto ?? 'FLOW';
  }

  fieldMeta(name: string): FeatureMeta {
    return (
      FEATURE_METADATA[name] ?? {
        group: 'psfe',
        displayLabel: name,
        hint: 'Model input feature.',
      }
    );
  }

  groupCount(groupId: 'all' | FeatureGroup): number {
    if (groupId === 'all') return this.fields.length;
    return this.fields.filter(f => this.fieldMeta(f.name).group === groupId).length;
  }

  isFieldModified(name: string): boolean {
    if (!this.activePreset) return false;
    return String(this.values[name] ?? '') !== String(this.baselineValues[name] ?? '');
  }

  get modifiedCount(): number {
    if (!this.activePreset) return 0;
    let count = 0;
    for (const field of this.fields) {
      if (this.isFieldModified(field.name)) count++;
    }
    return count;
  }

  get currentPayloadSignature(): string {
    return this.fields.map(f => String(this.values[f.name] ?? '')).join('|');
  }

  get isStaleResult(): boolean {
    return (
      this.result !== null &&
      this.lastClassifiedSignature !== '' &&
      this.lastClassifiedSignature !== this.currentPayloadSignature
    );
  }

  get filteredFields(): Feature[] {
    const query = this.searchQuery.trim().toLowerCase();
    return this.fields.filter(field => {
      const meta = this.fieldMeta(field.name);
      if (this.selectedGroup !== 'all' && meta.group !== this.selectedGroup) {
        return false;
      }
      if (this.onlyModified && !this.isFieldModified(field.name)) {
        return false;
      }
      if (this.onlyNonZero) {
        const val = this.values[field.name];
        if (val === null || val === '' || val === 0 || val === '0') {
          return false;
        }
      }
      if (!query) return true;
      return (
        field.name.toLowerCase().includes(query) ||
        meta.displayLabel.toLowerCase().includes(query) ||
        meta.hint.toLowerCase().includes(query)
      );
    });
  }

  resetFilters() {
    this.selectedGroup = 'all';
    this.searchQuery = '';
    this.onlyNonZero = false;
    this.onlyModified = false;
  }

  trackField(_index: number, field: Feature) {
    return field.name;
  }

  loadPreset(name: string, forceClassify = false) {
    this.activePreset = name;
    this.error = '';
    const preset = this.presets[name];
    if (!preset) return;
    for (const field of this.fields) {
      const val = preset[field.name] ?? null;
      this.values[field.name] = val;
      this.baselineValues[field.name] = val;
    }
    if (forceClassify || this.autoClassify) {
      this.submit();
    } else {
      this.cdr.markForCheck();
    }
  }

  resetToPreset() {
    if (!this.activePreset) return;
    this.loadPreset(this.activePreset, this.autoClassify);
  }

  clearForm() {
    this.activePreset = '';
    this.error = '';
    this.result = null;
    this.allProbabilities = [];
    this.lastClassifiedSignature = '';
    for (const field of this.fields) {
      this.values[field.name] = null;
      this.baselineValues[field.name] = null;
    }
    this.cdr.markForCheck();
  }

  setBinaryValue(name: string, val: 0 | 1) {
    this.values[name] = val;
  }

  get isNormalPrediction(): boolean {
    return String(this.result?.prediction) === 'Normal';
  }

  get confidencePercent(): string {
    if (!this.result?.probabilities?.length) return 'N/A';
    const maxP = Math.max(...this.result.probabilities);
    return (maxP * 100).toFixed(2) + '%';
  }

  get visibleProbabilities(): ClassProbBar[] {
    return this.showAllClasses ? this.allProbabilities : this.allProbabilities.slice(0, 5);
  }

  get currentClassInfo() {
    const label = String(this.result?.prediction || '');
    return (
      CLASS_DESCRIPTIONS[label] ?? {
        category: label === 'Normal' ? 'Benign IIoT Telemetry' : `Intrusion Class: ${label}`,
        explanation: `Classified across 15 Edge-IIoTset categories using the 62-feature PP-PSFE XGBoost pipeline.`,
        action: label === 'Normal' ? 'Permit flow.' : 'Raise alert and inspect source endpoint.',
      }
    );
  }

  get anatomy() {
    const num = (key: string) => Number(this.values[key] ?? 0) || 0;
    const str = (key: string) => String(this.values[key] ?? '0');

    const servicePort = num('psfe_service_port');
    const ephemeralPort = num('psfe_ephemeral_port');
    const portSpan = num('psfe_port_span');
    const dir = num('psfe_pkt_direction');
    const entropy = Math.max(0, Math.min(8, num('psfe_tcp_pay_entropy')));
    const payloadBytes = num('psfe_tcp_pay_bytelen');

    const activeProtocols = [
      {
        name: 'TCP',
        active: num('tcp.flags') > 0 || num('tcp.len') > 0 || num('tcp.seq') > 0 || num('tcp.ack') > 0,
      },
      {
        name: 'HTTP',
        active: num('psfe_is_http_service') === 1 || str('http.request.method') !== '0',
      },
      {
        name: 'MQTT',
        active: num('psfe_is_mqtt_service') === 1 || num('mqtt.msgtype') > 0 || str('mqtt.protoname') !== '0',
      },
      { name: 'UDP', active: num('psfe_udp_active') === 1 || num('udp.stream') > 0 },
      { name: 'DNS', active: num('dns.qry.name') > 0 || num('dns.qry.name.len') > 0 },
      { name: 'ICMP', active: num('icmp.checksum') > 0 || num('icmp.seq_le') > 0 },
      { name: 'ARP', active: num('arp.opcode') > 0 },
    ];

    const tcpFlags = [
      { name: 'SYN', active: num('tcp.connection.syn') === 1 },
      { name: 'SYN-ACK', active: num('tcp.connection.synack') === 1 },
      { name: 'ACK', active: num('tcp.flags.ack') === 1 },
      { name: 'FIN', active: num('tcp.connection.fin') === 1 },
      { name: 'RST', active: num('tcp.connection.rst') === 1 },
    ];

    const signals: { label: string; severity: 'info' | 'alert' }[] = [];
    if (num('psfe_is_http_service') === 1) signals.push({ label: 'HTTP Port', severity: 'info' });
    if (num('psfe_is_mqtt_service') === 1) signals.push({ label: 'MQTT Broker :1883', severity: 'info' });
    if (num('psfe_is_iot_c2_service') === 1) signals.push({ label: 'IoT C2 Port', severity: 'alert' });
    if (num('psfe_is_boundary_probe') === 1) signals.push({ label: 'Port 65535 Probe', severity: 'alert' });
    if (num('psfe_tcp_opt_has_mss') === 1) signals.push({ label: 'TCP MSS Option', severity: 'info' });
    if (num('psfe_tcp_opt_has_ts') === 1) signals.push({ label: 'TCP Timestamp Option', severity: 'info' });
    if (num('psfe_app_sqli_flag') === 1) signals.push({ label: 'SQLi Token Match', severity: 'alert' });
    if (num('psfe_app_xss_flag') === 1) signals.push({ label: 'XSS Payload Match', severity: 'alert' });
    if (num('psfe_app_upload_flag') === 1) signals.push({ label: 'HTTP Upload Flag', severity: 'alert' });
    if (num('psfe_app_auth_flag') === 1) signals.push({ label: 'Auth Payload Flag', severity: 'alert' });
    if (num('psfe_app_timeout_flag') === 1) signals.push({ label: 'App Timeout', severity: 'alert' });

    const entropyZone =
      payloadBytes === 0
        ? 'Empty Payload'
        : entropy < 2.2
          ? 'Low / Structured'
          : entropy < 3.4
            ? 'Text / Protocol'
            : 'Dense / Encrypted';

    return {
      servicePort,
      ephemeralPort,
      portSpan,
      directionLabel: dir > 0 ? 'Client -> Service (+1)' : dir < 0 ? 'Service -> Client (-1)' : 'Symmetric (0)',
      activeProtocols,
      tcpFlags,
      entropy,
      entropyPct: (entropy / 8) * 100,
      entropyZone,
      payloadBytes,
      signals,
    };
  }

  private buildValidatedPayload(): Record<string, string | number> | null {
    const payload: Record<string, string | number> = {};
    for (const field of this.fields) {
      const value = this.values[field.name];
      if (value === null || value === '') {
        this.error = `Enter a value for ${this.fieldMeta(field.name).displayLabel} (${field.name}).`;
        this.cdr.markForCheck();
        return null;
      }
      if (field.kind === 'number') {
        const numeric = Number(value);
        if (!Number.isFinite(numeric)) {
          this.error = `Invalid numeric value for ${field.name}.`;
          this.cdr.markForCheck();
          return null;
        }
        if (
          (field.min !== undefined && numeric < field.min) ||
          (field.max !== undefined && numeric > field.max)
        ) {
          this.error = `Out-of-range value for ${field.name}.`;
          this.cdr.markForCheck();
          return null;
        }
        payload[field.name] = numeric;
      } else {
        payload[field.name] = String(value);
      }
    }
    return payload;
  }

  private buildAllProbabilities(res: PredictionResponse) {
    const classProbs = res.class_probabilities;
    if (classProbs) {
      this.allProbabilities = Object.entries(classProbs)
        .map(([name, prob]) => ({
          name,
          prob: Number(prob),
          percent: (Number(prob) * 100).toFixed(2) + '%',
        }))
        .sort((a, b) => b.prob - a.prob);
    } else {
      this.allProbabilities = [];
    }
  }

  private appendHistory(
    res: PredictionResponse,
    payload: Record<string, string | number>,
    latencyMs: number | null,
    mode: 'Live API' | 'Static Replay'
  ) {
    const label = String(res.prediction);
    const maxProb = res.probabilities?.length
      ? (Math.max(...res.probabilities) * 100).toFixed(2) + '%'
      : 'N/A';

    const sourceLabel = this.activePreset
      ? this.modifiedCount > 0
        ? `${this.activePreset} (Edited)`
        : this.activePreset
      : 'Custom JSON / Manual';

    const entry: ClassificationLogEntry = {
      id: this.nextLogId++,
      timestamp: new Date().toLocaleTimeString([], { hour12: false }),
      sourceLabel,
      modifiedCount: this.modifiedCount,
      prediction: label,
      isNormal: label === 'Normal',
      confidence: maxProb,
      latencyMs,
      mode,
      snapshot: { ...payload },
      response: res,
    };

    this.history = [entry, ...this.history].slice(0, 30);
  }

  submit() {
    this.error = '';
    const payload = this.buildValidatedPayload();
    if (!payload) return;

    const signature = this.currentPayloadSignature;

    if (this.deployedStatic) {
      const fallback = STATIC_PRESET_RESULTS[this.activePreset] ?? STATIC_PRESET_RESULTS['Normal'];
      this.result = fallback;
      this.lastLatencyMs = 0;
      this.lastClassifiedSignature = signature;
      this.buildAllProbabilities(fallback);
      this.appendHistory(fallback, payload, 0, 'Static Replay');
      this.cdr.markForCheck();
      return;
    }

    this.loading = true;
    const started = typeof performance !== 'undefined' ? performance.now() : Date.now();
    this.cdr.markForCheck();

    this.api.predict(payload).subscribe({
      next: result => {
        const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
        const elapsed = Math.max(1, Math.round(now - started));
        this.result = result;
        this.lastLatencyMs = elapsed;
        this.lastClassifiedSignature = signature;
        this.apiState = 'online';
        this.buildAllProbabilities(result);
        this.appendHistory(result, payload, elapsed, 'Live API');
        this.loading = false;
        this.cdr.markForCheck();
      },
      error: err => {
        this.error =
          `Inference error ${err.status || ''}: ` +
          (err.error?.error || err.message || 'Unable to reach Flask API on 127.0.0.1:5050.');
        if (!err.status || err.status === 0 || err.status >= 502) {
          this.apiState = 'offline';
        }
        this.loading = false;
        this.cdr.markForCheck();
      },
    });
  }

  loadHistoryEntry(entry: ClassificationLogEntry) {
    this.activePreset = '';
    this.error = '';
    for (const field of this.fields) {
      this.values[field.name] = entry.snapshot[field.name] ?? null;
      this.baselineValues[field.name] = entry.snapshot[field.name] ?? null;
    }
    this.result = entry.response;
    this.lastLatencyMs = entry.latencyMs;
    this.lastClassifiedSignature = this.currentPayloadSignature;
    this.buildAllProbabilities(entry.response);
    this.activeTab = 'classifier';
    this.cdr.markForCheck();
  }

  clearHistory() {
    this.history = [];
  }

  /* JSON Modal Inspector */
  openJsonModal() {
    const out: Record<string, string | number | null> = {};
    for (const field of this.fields) {
      out[field.name] = this.values[field.name] ?? null;
    }
    this.jsonDraft = JSON.stringify(out, null, 2);
    this.jsonError = '';
    this.jsonCopied = false;
    this.jsonModalOpen = true;
  }

  closeJsonModal() {
    this.jsonModalOpen = false;
  }

  async copyJson() {
    if (typeof navigator === 'undefined' || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(this.jsonDraft);
      this.jsonCopied = true;
      setTimeout(() => {
        this.jsonCopied = false;
        this.cdr.markForCheck();
      }, 1800);
    } catch {
      this.jsonError = 'Clipboard access denied by browser.';
    }
  }

  applyJsonPayload(andClassify: boolean) {
    this.jsonError = '';
    let parsed: unknown;
    try {
      parsed = JSON.parse(this.jsonDraft);
    } catch {
      this.jsonError = 'Invalid JSON syntax.';
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      this.jsonError = 'JSON payload must be an object with 62 feature keys.';
      return;
    }

    const record = parsed as Record<string, unknown>;
    const expectedKeys = new Set(this.fields.map(f => f.name));
    const missing = this.fields.filter(f => !(f.name in record)).map(f => f.name);
    const extra = Object.keys(record).filter(k => !expectedKeys.has(k));

    if (missing.length || extra.length) {
      this.jsonError = `Schema mismatch — missing: ${missing.length}, unexpected: ${extra.length}.`;
      return;
    }

    this.activePreset = '';
    for (const field of this.fields) {
      const raw = record[field.name];
      if (field.kind === 'number') {
        const numeric = Number(raw);
        if (!Number.isFinite(numeric)) {
          this.jsonError = `Expected finite number for "${field.name}".`;
          return;
        }
        this.values[field.name] = numeric;
      } else {
        this.values[field.name] = String(raw);
      }
      this.baselineValues[field.name] = this.values[field.name];
    }

    this.jsonModalOpen = false;
    this.cdr.markForCheck();
    if (andClassify) {
      this.submit();
    }
  }

  /* Interactive Benchmark Helpers */
  metricDisplay(model: ModelBenchmark): string {
    switch (this.selectedMetric) {
      case 'accuracy': return model.accuracy;
      case 'macroF1': return model.macroF1;
      case 'rocAuc': return model.rocAuc;
      case 'prAuc': return model.prAuc;
      case 'overfitGap': return model.overfitGap;
      case 'latency': return model.latency;
    }
  }

  metricBarPercent(model: ModelBenchmark): number {
    switch (this.selectedMetric) {
      case 'accuracy': return model.accuracyNum;
      case 'macroF1': return model.macroF1Num * 100;
      case 'rocAuc': return model.rocAucNum * 100;
      case 'prAuc': return model.prAucNum * 100;
      case 'overfitGap': return Math.min(100, (model.overfitGapNum / 0.025) * 100);
      case 'latency': return Math.min(100, (model.latencyNum / 20) * 100);
    }
  }

  get activeMetricDirection(): string {
    return this.benchmarkMetrics.find(m => m.key === this.selectedMetric)?.direction ?? '';
  }

  isMetricWinner(model: ModelBenchmark): boolean {
    switch (this.selectedMetric) {
      case 'accuracy': return model.accuracyNum === 96.49;
      case 'macroF1': return model.macroF1Num === 0.9618;
      case 'rocAuc': return model.rocAucNum === 0.9991;
      case 'prAuc': return model.prAucNum === 0.9888;
      case 'overfitGap': return model.overfitGapNum === 0.0016;
      case 'latency': return model.latencyNum === 0.43;
    }
  }
}
