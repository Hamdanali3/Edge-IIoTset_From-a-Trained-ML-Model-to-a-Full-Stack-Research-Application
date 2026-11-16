import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface HealthResponse {
  status: string;
  features: number;
  task: string;
  classes: string[];
}

export interface PredictionResponse {
  prediction: string | number;
  predicted_class_index?: number;
  task: string;
  probabilities?: number[];
  class_probabilities?: Record<string, number>;
  disclaimer?: string;
}

@Injectable({ providedIn: 'root' })
export class PredictionService {
  private http = inject(HttpClient);

  health(): Observable<HealthResponse> {
    return this.http.get<HealthResponse>('/api/health');
  }

  predict(payload: Record<string, string | number>): Observable<PredictionResponse> {
    return this.http.post<PredictionResponse>('/api/predict', payload);
  }
}
