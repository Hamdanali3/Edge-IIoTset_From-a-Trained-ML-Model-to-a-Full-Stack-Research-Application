import { ChangeDetectorRef, Component, OnInit, inject } from '@angular/core';
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
  role: string;
  accuracyNum: number;
  accuracy: string;
  macroF1Num: number;
  macroF1: string;
  latencyNum: number;
  latency: string;
  gap: string;
  best?: boolean;
}

export interface AblationRow {
  label: string;
  features: number;
  accuracyNum: number;
  accuracy: string;
  macroF1: string;
  note: string;
  status?: 'best' | 'drop';
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
    disclaimer: 'Research prototype on Edge-IIoTset (Static Replay Mode).'
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
    disclaimer: 'Research prototype on Edge-IIoTset (Static Replay Mode).'
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
    disclaimer: 'Research prototype on Edge-IIoTset (Static Replay Mode).'
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
    disclaimer: 'Research prototype on Edge-IIoTset (Static Replay Mode).'
  }
};

const PRESET_CARDS: Record<string, { title: string; subtitle: string; tag: string }> = {
  Normal: {
    title: 'Normal Sensor Telemetry',
    subtitle: 'Routine MQTT broker disconnect flow',
    tag: 'MQTT :1883',
  },
  DDoS_TCP: {
    title: 'DDoS TCP Flood',
    subtitle: 'Empty-payload RST/ACK volumetric burst',
    tag: 'TCP :80',
  },
  SQL_injection: {
    title: 'SQL Injection Probe',
    subtitle: 'HTTP GET query with SQL syntax markers',
    tag: 'HTTP :80',
  },
  Ransomware: {
    title: 'Ransomware C2 Traffic',
    subtitle: 'High-entropy encrypted payload on C2 port',
    tag: 'Port :4321',
  },
};

const CLASS_EXPLANATIONS: Record<string, { summary: string; action: string }> = {
  Normal: {
    summary: 'Standard MQTT sensor traffic on port 1883 with normal TCP flags and no malicious signatures.',
    action: 'Allow flow normally.',
  },
  DDoS_TCP: {
    summary: 'Volumetric TCP control traffic targeting port 80 with RST flags and zero application payload.',
    action: 'Rate-limit source subnet and enable SYN cookies.',
  },
  SQL_injection: {
    summary: 'HTTP request carrying SQL injection query patterns (psfe_app_sqli_flag=1) and elevated URI length.',
    action: 'Block HTTP request at the WAF and audit endpoint queries.',
  },
  Ransomware: {
    summary: 'Encrypted outbound command-and-control traffic on port 4321 with high payload entropy.',
    action: 'Quarantine the IIoT host and block the destination port.',
  },
};

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App implements OnInit {
  readonly fields = FEATURES;
  readonly featureGroups = FEATURE_GROUPS;
  readonly presets = SAMPLE_PRESETS;
  readonly presetNames = Object.keys(SAMPLE_PRESETS);
  readonly deployedStatic =
    typeof window !== 'undefined' &&
    !['localhost', '127.0.0.1', ''].includes(window.location.hostname);

  readonly benchmarks: ModelBenchmark[] = [
    {
      name: 'XGBoost + PP-PSFE',
      role: 'Selected model · lowest error + 5x faster than LightGBM',
      accuracyNum: 96.49,
      accuracy: '96.49%',
      macroF1Num: 0.9618,
      macroF1: '0.9618',
      latencyNum: 3.54,
      latency: '3.54 ms',
      gap: '+0.0057',
      best: true,
    },
    {
      name: 'LightGBM',
      role: 'Leaf-wise gradient boosting',
      accuracyNum: 96.33,
      accuracy: '96.33%',
      macroF1Num: 0.9596,
      macroF1: '0.9596',
      latencyNum: 18.35,
      latency: '18.35 ms',
      gap: '+0.0210',
    },
    {
      name: 'Random Forest',
      role: 'Balanced bagging ensemble (150 trees)',
      accuracyNum: 94.38,
      accuracy: '94.38%',
      macroF1Num: 0.9414,
      macroF1: '0.9414',
      latencyNum: 10.35,
      latency: '10.35 ms',
      gap: '+0.0020',
    },
    {
      name: 'Logistic Regression',
      role: 'Linear baseline (struggles on HTTP attacks)',
      accuracyNum: 84.87,
      accuracy: '84.87%',
      macroF1Num: 0.8419,
      macroF1: '0.8419',
      latencyNum: 0.43,
      latency: '0.43 ms',
      gap: '+0.0016',
    },
  ];

  readonly randomAblation: AblationRow[] = [
    {
      label: 'Core + PP-PSFE (Proposed)',
      features: 62,
      accuracyNum: 96.57,
      accuracy: '96.57%',
      macroF1: '0.9621',
      note: '+7.60% recovery over cleaned core features alone',
      status: 'best',
    },
    {
      label: 'PP-PSFE minus raw ports',
      features: 59,
      accuracyNum: 92.64,
      accuracy: '92.64%',
      macroF1: '0.9237',
      note: 'Drops raw continuous port coordinates, keeps role flags',
    },
    {
      label: 'PP-PSFE minus all port group',
      features: 53,
      accuracyNum: 90.95,
      accuracy: '90.95%',
      macroF1: '0.9023',
      note: 'Removes all 9 Group A port-role features',
    },
    {
      label: 'Sanitized Core Only',
      features: 38,
      accuracyNum: 88.97,
      accuracy: '88.97%',
      macroF1: '0.8900',
      note: 'After deleting lab IPs, timestamps, URIs & payloads',
    },
  ];

  readonly temporalAblation: AblationRow[] = [
    {
      label: 'PP-PSFE minus raw ports',
      features: 59,
      accuracyNum: 91.70,
      accuracy: '91.70%',
      macroF1: '0.9151',
      note: 'Best temporal stability (+3.77% over core baseline)',
      status: 'best',
    },
    {
      label: 'Sanitized Core Only',
      features: 38,
      accuracyNum: 87.93,
      accuracy: '87.93%',
      macroF1: '0.8813',
      note: 'Baseline without engineered features',
    },
    {
      label: 'Core + Full PP-PSFE (with raw ports)',
      features: 62,
      accuracyNum: 79.40,
      accuracy: '79.40%',
      macroF1: '0.7638',
      note: 'Exposes chronological ephemeral-port drift across sessions',
      status: 'drop',
    },
    {
      label: 'Minus sequence/stream counters',
      features: 58,
      accuracyNum: 66.39,
      accuracy: '66.39%',
      macroF1: '0.6037',
      note: 'Exposes capture-order counter reliance (tcp.seq, udp.stream)',
      status: 'drop',
    },
  ];

  theme: 'light' | 'dark' = 'light';
  apiState: 'checking' | 'online' | 'offline' | 'static' = 'checking';
  apiLatencyMs: number | null = null;

  activePreset = 'Normal';
  values: Record<string, string | number | null> = {};
  baselineValues: Record<string, string | number | null> = {};

  showEditor = false;
  selectedGroup: 'all' | FeatureGroup = 'psfe';
  searchQuery = '';

  loading = false;
  error = '';
  result: PredictionResponse | null = null;
  lastLatencyMs: number | null = null;
  allProbabilities: ClassProbBar[] = [];
  showAllClasses = false;

  benchmarkMetric: 'accuracy' | 'macroF1' | 'latency' = 'accuracy';
  ablationSplit: 'random' | 'temporal' = 'random';

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

  private initTheme() {
    if (typeof window === 'undefined') return;
    try {
      const saved = window.localStorage?.getItem('edge-ids-theme');
      this.theme = saved === 'dark' ? 'dark' : 'light';
    } catch {
      this.theme = 'light';
    }
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', this.theme);
    }
  }

  toggleTheme() {
    this.theme = this.theme === 'light' ? 'dark' : 'light';
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', this.theme);
    }
    if (typeof window !== 'undefined') {
      try {
        window.localStorage?.setItem('edge-ids-theme', this.theme);
      } catch {
        // Ignore storage restrictions.
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

  presetCard(name: string) {
    return PRESET_CARDS[name] ?? { title: name, subtitle: 'Held-out packet sample', tag: 'Flow' };
  }

  fieldMeta(name: string): FeatureMeta {
    return (
      FEATURE_METADATA[name] ?? {
        group: 'psfe',
        displayLabel: name,
        hint: 'Input feature.',
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
    for (const f of this.fields) {
      if (this.isFieldModified(f.name)) count++;
    }
    return count;
  }

  get filteredFields(): Feature[] {
    const q = this.searchQuery.trim().toLowerCase();
    return this.fields.filter(field => {
      const meta = this.fieldMeta(field.name);
      if (this.selectedGroup !== 'all' && meta.group !== this.selectedGroup) {
        return false;
      }
      if (!q) return true;
      return (
        field.name.toLowerCase().includes(q) ||
        meta.displayLabel.toLowerCase().includes(q)
      );
    });
  }

  loadPreset(name: string, runNow = true) {
    this.activePreset = name;
    this.error = '';
    const preset = this.presets[name];
    if (!preset) return;
    for (const field of this.fields) {
      const val = preset[field.name] ?? null;
      this.values[field.name] = val;
      this.baselineValues[field.name] = val;
    }
    if (runNow) {
      this.submit();
    } else {
      this.cdr.markForCheck();
    }
  }

  setBinaryValue(name: string, val: 0 | 1) {
    this.values[name] = val;
  }

  get isNormalPrediction(): boolean {
    return String(this.result?.prediction) === 'Normal';
  }

  get confidencePercent(): string {
    if (!this.result?.probabilities?.length) return 'N/A';
    return (Math.max(...this.result.probabilities) * 100).toFixed(2) + '%';
  }

  get visibleProbabilities(): ClassProbBar[] {
    return this.showAllClasses ? this.allProbabilities : this.allProbabilities.slice(0, 5);
  }

  get explanation() {
    const label = String(this.result?.prediction || '');
    return (
      CLASS_EXPLANATIONS[label] ?? {
        summary: `Predicted as ${label} across the 15 Edge-IIoTset traffic categories.`,
        action: label === 'Normal' ? 'Allow flow.' : 'Trigger alert and inspect endpoint.',
      }
    );
  }

  get packetSnapshot() {
    const num = (k: string) => Number(this.values[k] ?? 0) || 0;
    const servicePort = num('psfe_service_port');
    const ephPort = num('psfe_ephemeral_port');
    const dir = num('psfe_pkt_direction');
    const entropy = Math.max(0, Math.min(4, num('psfe_tcp_pay_entropy')));
    const bytes = num('psfe_tcp_pay_bytelen');

    const signals: { label: string; alert: boolean }[] = [];
    if (num('psfe_is_mqtt_service') === 1) signals.push({ label: 'MQTT Broker', alert: false });
    if (num('psfe_is_http_service') === 1) signals.push({ label: 'HTTP Service', alert: false });
    if (num('tcp.connection.rst') === 1) signals.push({ label: 'TCP RST', alert: true });
    if (num('psfe_is_iot_c2_service') === 1) signals.push({ label: 'IoT C2 Port', alert: true });
    if (num('psfe_app_sqli_flag') === 1) signals.push({ label: 'SQLi Marker', alert: true });
    if (num('psfe_app_xss_flag') === 1) signals.push({ label: 'XSS Marker', alert: true });
    if (num('psfe_app_upload_flag') === 1) signals.push({ label: 'Upload Marker', alert: true });
    if (num('psfe_app_auth_flag') === 1) signals.push({ label: 'Auth Marker', alert: true });

    return {
      flowText: dir >= 0 ? `:${ephPort} → :${servicePort}` : `:${servicePort} → :${ephPort}`,
      bytes,
      entropy,
      entropyPct: (entropy / 4) * 100,
      signals: signals.length ? signals : [{ label: 'Standard Headers', alert: false }],
    };
  }

  get activeAblationRows(): AblationRow[] {
    return this.ablationSplit === 'random' ? this.randomAblation : this.temporalAblation;
  }

  benchmarkBarPct(m: ModelBenchmark): number {
    if (this.benchmarkMetric === 'accuracy') return m.accuracyNum;
    if (this.benchmarkMetric === 'macroF1') return m.macroF1Num * 100;
    return Math.min(100, (m.latencyNum / 20) * 100);
  }

  benchmarkValue(m: ModelBenchmark): string {
    if (this.benchmarkMetric === 'accuracy') return m.accuracy;
    if (this.benchmarkMetric === 'macroF1') return m.macroF1;
    return m.latency + ' / 1k';
  }

  submit() {
    this.error = '';
    const payload: Record<string, string | number> = {};
    for (const field of this.fields) {
      const value = this.values[field.name];
      if (value === null || value === '') {
        this.error = `Enter a value for ${this.fieldMeta(field.name).displayLabel} (${field.name}).`;
        this.cdr.markForCheck();
        return;
      }
      if (field.kind === 'number') {
        const numeric = Number(value);
        if (!Number.isFinite(numeric)) {
          this.error = `Invalid number for ${field.name}.`;
          this.cdr.markForCheck();
          return;
        }
        payload[field.name] = numeric;
      } else {
        payload[field.name] = String(value);
      }
    }

    if (this.deployedStatic) {
      const fallback = STATIC_PRESET_RESULTS[this.activePreset] ?? STATIC_PRESET_RESULTS['Normal'];
      this.result = fallback;
      this.lastLatencyMs = 0;
      this.buildProbabilities(fallback);
      this.cdr.markForCheck();
      return;
    }

    this.loading = true;
    const started = typeof performance !== 'undefined' ? performance.now() : Date.now();
    this.cdr.markForCheck();

    this.api.predict(payload).subscribe({
      next: res => {
        const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
        this.result = res;
        this.lastLatencyMs = Math.max(1, Math.round(now - started));
        this.apiState = 'online';
        this.buildProbabilities(res);
        this.loading = false;
        this.cdr.markForCheck();
      },
      error: err => {
        this.error =
          `API error ${err.status || ''}: ` +
          (err.error?.error || err.message || 'Check Flask server on port 5050.');
        if (!err.status || err.status === 0 || err.status >= 502) {
          this.apiState = 'offline';
        }
        this.loading = false;
        this.cdr.markForCheck();
      },
    });
  }

  private buildProbabilities(res: PredictionResponse) {
    if (!res.class_probabilities) {
      this.allProbabilities = [];
      return;
    }
    this.allProbabilities = Object.entries(res.class_probabilities)
      .map(([name, prob]) => ({
        name,
        prob: Number(prob),
        percent: (Number(prob) * 100).toFixed(2) + '%',
      }))
      .sort((a, b) => b.prob - a.prob);
  }

  /* JSON Modal */
  openJsonModal() {
    const out: Record<string, string | number | null> = {};
    for (const f of this.fields) {
      out[f.name] = this.values[f.name] ?? null;
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
      }, 1600);
    } catch {
      this.jsonError = 'Clipboard permission denied.';
    }
  }

  applyJsonPayload(runNow: boolean) {
    this.jsonError = '';
    let parsed: unknown;
    try {
      parsed = JSON.parse(this.jsonDraft);
    } catch {
      this.jsonError = 'Invalid JSON syntax.';
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      this.jsonError = 'Payload must be a 62-key JSON object.';
      return;
    }
    const obj = parsed as Record<string, unknown>;
    const expected = new Set(this.fields.map(f => f.name));
    const missing = this.fields.filter(f => !(f.name in obj)).length;
    const extra = Object.keys(obj).filter(k => !expected.has(k)).length;
    if (missing || extra) {
      this.jsonError = `Schema mismatch (missing ${missing}, unexpected ${extra}).`;
      return;
    }
    this.activePreset = '';
    for (const f of this.fields) {
      const raw = obj[f.name];
      if (f.kind === 'number') {
        const n = Number(raw);
        if (!Number.isFinite(n)) {
          this.jsonError = `Invalid number for ${f.name}.`;
          return;
        }
        this.values[f.name] = n;
      } else {
        this.values[f.name] = String(raw);
      }
      this.baselineValues[f.name] = this.values[f.name];
    }
    this.jsonModalOpen = false;
    if (runNow) {
      this.submit();
    } else {
      this.cdr.markForCheck();
    }
  }
}
