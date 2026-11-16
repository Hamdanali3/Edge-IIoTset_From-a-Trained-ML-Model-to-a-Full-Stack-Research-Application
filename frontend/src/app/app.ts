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

export interface AblationBar {
  shortLabel: string;
  subLabel: string;
  accuracy: number;
  barX: number;
  centerX: number;
  barY: number;
  barHeight: number;
  tone: 'best' | 'normal' | 'warn';
}

export interface HttpRecoveryPair {
  label: string;
  centerX: number;
  lrF1: number;
  xgbF1: number;
  lrY: number;
  lrH: number;
  xgbY: number;
  xgbH: number;
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
    disclaimer: 'Static replay mode.'
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
    disclaimer: 'Static replay mode.'
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
    disclaimer: 'Static replay mode.'
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
    disclaimer: 'Static replay mode.'
  }
};

const PRESET_LABELS: Record<string, { title: string; tag: string }> = {
  Normal: { title: 'Normal Telemetry', tag: 'MQTT :1883' },
  DDoS_TCP: { title: 'DDoS TCP Flood', tag: 'TCP :80' },
  SQL_injection: { title: 'SQL Injection', tag: 'HTTP :80' },
  Ransomware: { title: 'Ransomware C2', tag: 'Port :4321' },
};

const SHORT_CAPTIONS: Record<string, string> = {
  Normal: 'Clean MQTT broker session on port 1883 with zero threat markers.',
  DDoS_TCP: 'High-rate TCP RST/ACK burst on port 80 with empty payload.',
  SQL_injection: 'HTTP query carrying SQL syntax markers (psfe_app_sqli_flag=1).',
  Ransomware: 'High-entropy encrypted TCP flow targeting C2 port 4321.',
};

function buildAblationBars(
  items: { shortLabel: string; subLabel: string; accuracy: number; tone: 'best' | 'normal' | 'warn' }[]
): AblationBar[] {
  const centers = [98, 203, 308, 413];
  return items.map((item, idx) => {
    const h = Math.max(4, ((item.accuracy - 55) / 45) * 162);
    return {
      ...item,
      centerX: centers[idx],
      barX: centers[idx] - 27,
      barHeight: h,
      barY: 186 - h,
    };
  });
}

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

  readonly ringCircumference = 251.33;

  readonly randomBars = buildAblationBars([
    { shortLabel: 'Core (38)', subLabel: 'F1 0.89', accuracy: 88.97, tone: 'normal' },
    { shortLabel: 'No PortGrp (53)', subLabel: 'F1 0.90', accuracy: 90.95, tone: 'normal' },
    { shortLabel: 'Role Only (59)', subLabel: 'F1 0.92', accuracy: 92.64, tone: 'normal' },
    { shortLabel: 'PP-PSFE (62)', subLabel: 'F1 0.96', accuracy: 96.57, tone: 'best' },
  ]);

  readonly temporalBars = buildAblationBars([
    { shortLabel: 'No Seq (58)', subLabel: 'F1 0.60', accuracy: 66.39, tone: 'warn' },
    { shortLabel: 'Raw Ports (62)', subLabel: 'F1 0.76', accuracy: 79.40, tone: 'warn' },
    { shortLabel: 'Core (38)', subLabel: 'F1 0.88', accuracy: 87.93, tone: 'normal' },
    { shortLabel: 'Role Only (59)', subLabel: 'F1 0.92', accuracy: 91.70, tone: 'best' },
  ]);

  readonly paretoPoints = [
    { name: 'XGBoost', acc: '96.49%', ms: '3.54 ms', cx: 126.8, cy: 41.1, lx: 138, ly: 39, best: true },
    { name: 'LightGBM', acc: '96.33%', ms: '18.35 ms', cx: 423.0, cy: 42.7, lx: 356, ly: 32, best: false },
    { name: 'Random Forest', acc: '94.38%', ms: '10.35 ms', cx: 263.0, cy: 62.2, lx: 274, ly: 66, best: false },
    { name: 'Logistic Reg', acc: '84.87%', ms: '0.43 ms', cx: 64.6, cy: 157.3, lx: 76, ly: 161, best: false },
  ];

  readonly httpRecovery: HttpRecoveryPair[] = [
    { label: 'Password', lrF1: 0.4371, xgbF1: 0.8875 },
    { label: 'SQLi', lrF1: 0.5746, xgbF1: 0.9010 },
    { label: 'DDoS_HTTP', lrF1: 0.6067, xgbF1: 0.8562 },
    { label: 'Upload', lrF1: 0.6354, xgbF1: 0.9294 },
    { label: 'XSS', lrF1: 0.6585, xgbF1: 0.9285 },
  ].map((item, idx) => {
    const centers = [90, 174, 258, 342, 426];
    const lrH = item.lrF1 * 160;
    const xgbH = item.xgbF1 * 160;
    return {
      ...item,
      centerX: centers[idx],
      lrH,
      lrY: 186 - lrH,
      xgbH,
      xgbY: 186 - xgbH,
    };
  });

  theme: 'light' | 'dark' = 'light';
  apiState: 'checking' | 'online' | 'offline' | 'static' = 'checking';
  apiLatencyMs: number | null = null;

  activePreset = 'Normal';
  values: Record<string, string | number | null> = {};

  loading = false;
  error = '';
  result: PredictionResponse | null = null;
  lastLatencyMs: number | null = null;
  allProbabilities: ClassProbBar[] = [];
  showAllClasses = false;

  ablationSplit: 'random' | 'temporal' = 'random';
  chartMode: 'pareto' | 'httpF1' = 'pareto';

  editorModalOpen = false;
  selectedGroup: 'all' | FeatureGroup = 'psfe';
  searchQuery = '';

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

  presetLabel(name: string) {
    return PRESET_LABELS[name] ?? { title: name, tag: 'Flow' };
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
      this.values[field.name] = preset[field.name] ?? null;
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

  get confidenceFraction(): number {
    if (!this.result?.probabilities?.length) return 0;
    return Math.max(0, Math.min(1, Math.max(...this.result.probabilities)));
  }

  get confidencePercent(): string {
    if (!this.result?.probabilities?.length) return '—';
    return (this.confidenceFraction * 100).toFixed(2) + '%';
  }

  get ringDashOffset(): number {
    return this.ringCircumference * (1 - this.confidenceFraction);
  }

  get visibleProbabilities(): ClassProbBar[] {
    return this.showAllClasses ? this.allProbabilities : this.allProbabilities.slice(0, 4);
  }

  get shortCaption(): string {
    const label = String(this.result?.prediction || '');
    return (
      SHORT_CAPTIONS[label] ??
      `Classified across 15 Edge-IIoTset traffic classes.`
    );
  }

  get packetVisual() {
    const num = (k: string) => Number(this.values[k] ?? 0) || 0;
    const servicePort = num('psfe_service_port');
    const ephPort = num('psfe_ephemeral_port');
    const dir = num('psfe_pkt_direction');
    const entropy = Math.max(0, Math.min(4, num('psfe_tcp_pay_entropy')));
    const bytes = num('psfe_tcp_pay_bytelen');
    const proto =
      num('psfe_is_mqtt_service') === 1
        ? 'MQTT'
        : num('psfe_is_http_service') === 1
          ? 'HTTP'
          : num('psfe_is_iot_c2_service') === 1
            ? 'C2'
            : 'TCP';

    return {
      leftPort: dir >= 0 ? `:${ephPort}` : `:${servicePort}`,
      rightPort: dir >= 0 ? `:${servicePort}` : `:${ephPort}`,
      leftRole: dir >= 0 ? 'Client' : 'Service',
      rightRole: dir >= 0 ? 'Service' : 'Client',
      proto,
      bytes,
      entropy,
      entropyPct: (entropy / 4) * 100,
    };
  }

  get activeAblationBars(): AblationBar[] {
    return this.ablationSplit === 'random' ? this.randomBars : this.temporalBars;
  }

  submit() {
    this.error = '';
    const payload: Record<string, string | number> = {};
    for (const field of this.fields) {
      const value = this.values[field.name];
      if (value === null || value === '') {
        this.error = `Enter a value for ${field.name}.`;
        this.cdr.markForCheck();
        return;
      }
      if (field.kind === 'number') {
        const n = Number(value);
        if (!Number.isFinite(n)) {
          this.error = `Invalid number for ${field.name}.`;
          this.cdr.markForCheck();
          return;
        }
        payload[field.name] = n;
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
    }
    this.jsonModalOpen = false;
    if (runNow) {
      this.submit();
    } else {
      this.cdr.markForCheck();
    }
  }
}
