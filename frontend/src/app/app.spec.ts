import { TestBed } from '@angular/core/testing';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { App } from './app';
import { routes } from './app.routes';
import { FEATURES } from './feature-schema';
import { FEATURE_METADATA } from './feature-metadata';

describe('App', () => {
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create the app and render clean title', async () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();

    httpMock.expectOne('/api/health').flush({
      status: 'ok',
      features: 62,
      task: 'classification',
      classes: ['Normal'],
    });
    httpMock.expectOne('/api/predict').flush({
      prediction: 'Normal',
      predicted_class_index: 7,
      task: 'classification',
      probabilities: [0.999],
      class_probabilities: { Normal: 0.999 },
    });

    await fixture.whenStable();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h1')?.textContent).toContain('Edge-IIoTset');
  });

  it('should cover all 62 features in metadata and layer partitions', () => {
    expect(FEATURES.length).toBe(62);
    for (const f of FEATURES) {
      expect(FEATURE_METADATA[f.name]).toBeDefined();
    }

    const fixture = TestBed.createComponent(App);
    const app = fixture.componentInstance;
    const sum =
      app.groupCount('psfe') +
      app.groupCount('tcp') +
      app.groupCount('http') +
      app.groupCount('mqtt') +
      app.groupCount('link_net');
    expect(sum).toBe(62);
  });

  it('should switch ablation chart between random and temporal splits', () => {
    const fixture = TestBed.createComponent(App);
    const app = fixture.componentInstance;
    expect(app.ablationSplit).toBe('random');
    expect(app.activeAblationBars[3].accuracy).toBe(96.57);

    app.ablationSplit = 'temporal';
    expect(app.activeAblationBars[3].accuracy).toBe(91.70);
  });

  it('should toggle light and dark theme', () => {
    const fixture = TestBed.createComponent(App);
    const app = fixture.componentInstance;
    const initial = app.theme;
    app.toggleTheme();
    expect(app.theme).not.toBe(initial);
  });

  it('should bootstrap cleanly with appConfig providers', async () => {
    TestBed.resetTestingModule();
    const errors: unknown[] = [];
    const origError = console.error;
    console.error = (...args: unknown[]) => errors.push(args);
    const root = document.createElement('app-root');
    document.body.appendChild(root);
    try {
      const appRef = await bootstrapApplication(App, {
        providers: [
          provideBrowserGlobalErrorListeners(),
          provideRouter(routes),
          provideHttpClient(),
          provideHttpClientTesting(),
        ],
      });
      await appRef.whenStable();
      expect(errors.length).toBe(0);
      expect(root.querySelector('h1')?.textContent).toContain('Edge-IIoTset');
      expect(root.querySelectorAll('.sample-btn').length).toBe(4);
      expect(root.querySelectorAll('.svg-chart').length).toBe(2);
      appRef.destroy();
    } finally {
      console.error = origError;
      root.remove();
    }
  });
});
