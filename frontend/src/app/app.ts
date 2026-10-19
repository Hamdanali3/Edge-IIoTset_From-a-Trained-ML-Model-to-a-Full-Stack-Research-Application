import { Component, ChangeDetectorRef, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { FEATURES, Feature, SAMPLE_PRESETS } from './feature-schema';
import { PredictionService, PredictionResponse } from './prediction.service';

export interface ClassProbBar {
  name: string;
  prob: number;
  percent: string;
}

export interface ModelBenchmark {
  name: string;
  accuracy: string;
  macroF1: string;
  rocAuc: string;
  prAuc: string;
  overfitGap: string;
  latency: string;
  best?: boolean;
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
    disclaimer: 'Research/teaching prototype only. Edge-IIoTset 15-class intrusion detection (Static Demo Replay).'
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
    disclaimer: 'Research/teaching prototype only. Edge-IIoTset 15-class intrusion detection (Static Demo Replay).'
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
    disclaimer: 'Research/teaching prototype only. Edge-IIoTset 15-class intrusion detection (Static Demo Replay).'
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
    disclaimer: 'Research/teaching prototype only. Edge-IIoTset 15-class intrusion detection (Static Demo Replay).'
  }
};

const CLASS_DESCRIPTIONS: Record<string, { category: string; explanation: string; action: string }> = {
  Normal: {
    category: 'Benign IIoT Telemetry (Safe)',
    explanation: 'Legitimate MQTT/TCP sensor telemetry with standard broker port (1883), clean TCP state transitions, and zero malicious payload signatures.',
    action: 'Allow packet flow. No firewall intervention required.'
  },
  DDoS_TCP: {
    category: 'Volumetric Transport-Layer Attack (DDoS)',
    explanation: 'High-rate TCP SYN flood targeting edge gateway ports with anomalous ephemeral port spans, zero application payload, and incomplete 3-way handshakes.',
    action: 'Block source flow at Edge Gateway and enable TCP SYN cookies / rate-limiting.'
  },
  SQL_injection: {
    category: 'Application-Layer Injection Attack (Web/API)',
    explanation: 'HTTP GET/POST request carrying SQL query manipulation tokens (psfe_app_sqli_flag=1, elevated URI query length and payload entropy).',
    action: 'Drop HTTP request immediately via WAF rule and isolate source session.'
  },
  Ransomware: {
    category: 'Malware / Command-and-Control (C2) Intrusion',
    explanation: 'Encrypted C2 / file-extortion TCP traffic exhibiting high payload byte entropy, anomalous MSS/TS TCP option signatures, and non-standard service ports.',
    action: 'Quarantine affected IIoT node immediately and block outbound C2 port.'
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
  readonly fields = FEATURES;
  readonly presets = SAMPLE_PRESETS;
  readonly presetNames = Object.keys(SAMPLE_PRESETS);
  readonly deployedStatic = !['localhost', '127.0.0.1']
    .includes(window.location.hostname);

  readonly benchmarks: ModelBenchmark[] = [
    { name: 'Logistic Regression (Linear Baseline)', accuracy: '84.87%', macroF1: '0.8419', rocAuc: '0.9829', prAuc: '0.8656', overfitGap: '+0.0016', latency: '0.43 ms' },
    { name: 'Random Forest (Bagging Ensemble)', accuracy: '94.38%', macroF1: '0.9414', rocAuc: '0.9978', prAuc: '0.9768', overfitGap: '+0.0020', latency: '10.35 ms' },
    { name: 'LightGBM (Leaf-Wise GBDT)', accuracy: '96.33%', macroF1: '0.9596', rocAuc: '0.9991', prAuc: '0.9888', overfitGap: '+0.0210', latency: '18.35 ms' },
    { name: 'XGBoost + PP-PSFE (Selected Best Model)', accuracy: '96.49%', macroF1: '0.9618', rocAuc: '0.9991', prAuc: '0.9874', overfitGap: '+0.0057', latency: '3.54 ms', best: true },
  ];

  activePreset = 'Normal';
  values: Record<string, string | number | null> = {};
  loading = false;
  error = '';
  result: PredictionResponse | null = null;
  topProbabilities: ClassProbBar[] = [];

  private api = inject(PredictionService);
  private cdr = inject(ChangeDetectorRef);

  ngOnInit() {
    this.loadPreset('Normal', true);
  }

  trackField(_index: number, field: Feature) {
    return field.name;
  }

  loadPreset(name: string, autoPredict = true) {
    this.activePreset = name;
    this.error = '';
    this.result = null;
    const preset = this.presets[name];
    if (!preset) return;
    for (const field of this.fields) {
      this.values[field.name] = preset[field.name] ?? null;
    }
    this.cdr.detectChanges();
    if (autoPredict) {
      this.submit();
    }
  }

  clearForm() {
    this.activePreset = '';
    this.error = '';
    this.result = null;
    this.topProbabilities = [];
    for (const field of this.fields) {
      this.values[field.name] = null;
    }
    this.cdr.detectChanges();
  }

  get isNormalPrediction(): boolean {
    return String(this.result?.prediction) === 'Normal';
  }

  get confidencePercent(): string {
    if (!this.result?.probabilities?.length) return 'N/A';
    const maxP = Math.max(...this.result.probabilities);
    return (maxP * 100).toFixed(2) + '%';
  }

  get currentClassInfo() {
    const label = String(this.result?.prediction || '');
    return CLASS_DESCRIPTIONS[label] ?? {
      category: label === 'Normal' ? 'Benign IIoT Telemetry' : `Cyberattack Class: ${label}`,
      explanation: `Classified by the 62-feature PP-PSFE XGBoost pipeline across 15 Edge-IIoTset traffic classes.`,
      action: label === 'Normal' ? 'Allow packet flow.' : 'Trigger IDS alert and inspect flow telemetry.'
    };
  }

  private buildTopProbabilities(res: PredictionResponse) {
    const classProbs = res.class_probabilities;
    if (classProbs) {
      this.topProbabilities = Object.entries(classProbs)
        .map(([name, prob]) => ({
          name,
          prob: Number(prob),
          percent: (Number(prob) * 100).toFixed(2) + '%'
        }))
        .sort((a, b) => b.prob - a.prob)
        .slice(0, 5);
    } else {
      this.topProbabilities = [];
    }
  }

  submit() {
    this.error = '';
    this.result = null;
    this.topProbabilities = [];

    const payload: Record<string, string | number> = {};
    for (const field of this.fields) {
      const value = this.values[field.name];
      if (value === null || value === '') {
        this.error = `Enter a value for ${field.label}`;
        this.cdr.detectChanges();
        return;
      }
      if (field.kind === 'number') {
        const numeric = Number(value);
        if (!Number.isFinite(numeric)) {
          this.error = `Invalid number for ${field.label}`;
          this.cdr.detectChanges();
          return;
        }
        if ((field.min !== undefined && numeric < field.min) ||
            (field.max !== undefined && numeric > field.max)) {
          this.error = `Out-of-range value for ${field.label}`;
          this.cdr.detectChanges();
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
      this.buildTopProbabilities(fallback);
      this.cdr.detectChanges();
      return;
    }

    this.loading = true;
    this.cdr.detectChanges();

    this.api.predict(payload).subscribe({
      next: result => {
        this.result = result;
        this.buildTopProbabilities(result);
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: err => {
        this.error = `API error ${err.status || ''}: ` +
          (err.error?.error || err.message || 'Check Flask terminal on port 5050');
        this.loading = false;
        this.cdr.detectChanges();
      },
    });
  }
}
