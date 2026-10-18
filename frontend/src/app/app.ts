import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { FEATURES, Feature, SAMPLE_PRESETS } from './feature-schema';
import { PredictionService, PredictionResponse } from './prediction.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  readonly fields = FEATURES;
  readonly presets = SAMPLE_PRESETS;
  readonly presetNames = Object.keys(SAMPLE_PRESETS);
  readonly deployedStatic = !['localhost', '127.0.0.1']
    .includes(window.location.hostname);
  values: Record<string, string | number | null> = {};
  loading = false;
  error = '';
  result: PredictionResponse | null = null;
  private api = inject(PredictionService);

  constructor() {
    this.loadPreset('Normal');
  }

  trackField(_index: number, field: Feature) {
    return field.name;
  }

  loadPreset(name: string) {
    this.error = '';
    this.result = null;
    const preset = this.presets[name];
    if (!preset) return;
    for (const field of this.fields) {
      this.values[field.name] = preset[field.name] ?? null;
    }
  }

  clearForm() {
    this.error = '';
    this.result = null;
    for (const field of this.fields) {
      this.values[field.name] = null;
    }
  }

  submit() {
    this.error = '';
    this.result = null;
    if (this.deployedStatic) {
      this.error = 'Static GitHub Pages demo: start Angular + Flask locally for predictions.';
      return;
    }
    const payload: Record<string, string | number> = {};
    for (const field of this.fields) {
      const value = this.values[field.name];
      if (value === null || value === '') {
        this.error = `Enter a value for ${field.label}`;
        return;
      }
      if (field.kind === 'number') {
        const numeric = Number(value);
        if (!Number.isFinite(numeric)) {
          this.error = `Invalid number for ${field.label}`;
          return;
        }
        if ((field.min !== undefined && numeric < field.min) ||
            (field.max !== undefined && numeric > field.max)) {
          this.error = `Out-of-range value for ${field.label}`;
          return;
        }
        payload[field.name] = numeric;
      } else {
        payload[field.name] = String(value);
      }
    }
    this.loading = true;
    this.api.predict(payload).subscribe({
      next: result => {
        this.result = result;
        this.loading = false;
      },
      error: err => {
        this.error = `API error ${err.status || ''}: ` +
          (err.error?.error || err.message || 'Check Flask terminal');
        this.loading = false;
      },
    });
  }
}
