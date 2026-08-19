/**
 * High-tech UI Sound Effects using Web Audio API.
 * Generates sci-fi style interface sounds without external assets.
 */

const AudioContextClass = (window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext);
let audioCtx: AudioContext | null = null;

function getContext(): AudioContext {
  if (!audioCtx) {
    audioCtx = new AudioContextClass();
  }
  return audioCtx;
}

const GAIN_MASTER = 0.15; // Global volume

let noiseBuffer: AudioBuffer | null = null;

function getNoiseBuffer(ctx: AudioContext): AudioBuffer {
  if (!noiseBuffer) {
    const bufferSize = ctx.sampleRate * 2; // 2 seconds of noise
    noiseBuffer = ctx.createBuffer(1, bufferSize, ctx.sampleRate);
    const output = noiseBuffer.getChannelData(0);
    for (let i = 0; i < bufferSize; i++) {
      output[i] = Math.random() * 2 - 1;
    }
  }
  return noiseBuffer;
}

/**
 * Play a cinematic rocket launch sound.
 */
export function playRocketLaunchSound() {
  try {
    const ctx = getContext();
    if (ctx.state === 'suspended') ctx.resume();

    const t = ctx.currentTime;
    const duration = 2.0;

    // 1. Low rumble (Filtered Noise)
    const noise = ctx.createBufferSource();
    noise.buffer = getNoiseBuffer(ctx);
    noise.loop = true;

    const noiseFilter = ctx.createBiquadFilter();
    noiseFilter.type = 'lowpass';
    noiseFilter.frequency.setValueAtTime(50, t);
    noiseFilter.frequency.exponentialRampToValueAtTime(1200, t + duration);

    const noiseGain = ctx.createGain();
    noiseGain.gain.setValueAtTime(0, t);
    noiseGain.gain.linearRampToValueAtTime(GAIN_MASTER * 0.8, t + 0.2);
    noiseGain.gain.exponentialRampToValueAtTime(0.01, t + duration);

    noise.connect(noiseFilter);
    noiseFilter.connect(noiseGain);
    noiseGain.connect(ctx.destination);

    // 2. Engine Thrust (Low Sawtooth)
    const engine = ctx.createOscillator();
    engine.type = 'sawtooth';
    engine.frequency.setValueAtTime(30, t);
    engine.frequency.exponentialRampToValueAtTime(80, t + duration);

    const engineGain = ctx.createGain();
    engineGain.gain.setValueAtTime(0, t);
    engineGain.gain.linearRampToValueAtTime(GAIN_MASTER * 0.4, t + 0.1);
    engineGain.gain.exponentialRampToValueAtTime(0.01, t + duration);

    engine.connect(engineGain);
    engineGain.connect(ctx.destination);

    // 3. Ignition Spark (High frequency burst)
    const spark = ctx.createOscillator();
    spark.type = 'square';
    spark.frequency.setValueAtTime(1000, t);
    spark.frequency.linearRampToValueAtTime(100, t + 0.1);
    
    const sparkGain = ctx.createGain();
    sparkGain.gain.setValueAtTime(GAIN_MASTER * 0.3, t);
    sparkGain.gain.exponentialRampToValueAtTime(0.01, t + 0.1);

    spark.connect(sparkGain);
    sparkGain.connect(ctx.destination);

    // Start everything
    noise.start(t);
    engine.start(t);
    spark.start(t);

    noise.stop(t + duration);
    engine.stop(t + duration);
    spark.stop(t + 0.1);

  } catch {
    // Ignore audio errors
  }
}

/**
 * Play a high-tech "blip" or "click" sound.
 */
export function playClickSound() {
  try {
    const ctx = getContext();
    if (ctx.state === 'suspended') ctx.resume();

    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.connect(gain);
    gain.connect(ctx.destination);

    // High pitched blip
    osc.type = 'sine';
    osc.frequency.setValueAtTime(800, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(1200, ctx.currentTime + 0.05);

    gain.gain.setValueAtTime(GAIN_MASTER, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.05);

    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.05);
  } catch {
    // Ignore audio errors
  }
}

/**
 * Play a "processing" or "initialization" sound (rising telemetry).
 */
export function playInitSound() {
  try {
    const ctx = getContext();
    if (ctx.state === 'suspended') ctx.resume();

    const t = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.type = 'square';
    osc.frequency.setValueAtTime(200, t);
    osc.frequency.linearRampToValueAtTime(800, t + 0.3);

    // Stutter effect
    gain.gain.setValueAtTime(0, t);
    gain.gain.linearRampToValueAtTime(GAIN_MASTER * 0.5, t + 0.05);
    gain.gain.linearRampToValueAtTime(0, t + 0.3);

    osc.start(t);
    osc.stop(t + 0.3);

    // Add a second layer (noise-like)
    const osc2 = ctx.createOscillator();
    const gain2 = ctx.createGain();
    osc2.connect(gain2);
    gain2.connect(ctx.destination);
    osc2.type = 'sawtooth';
    osc2.frequency.setValueAtTime(100, t);
    osc2.frequency.exponentialRampToValueAtTime(1000, t + 0.4);
    gain2.gain.setValueAtTime(GAIN_MASTER * 0.2, t);
    gain2.gain.exponentialRampToValueAtTime(0.01, t + 0.4);
    osc2.start(t);
    osc2.stop(t + 0.4);

  } catch {
    // Ignore audio errors
  }
}

/**
 * Play a "success" chime (major chord).
 */
export function playSuccessSound() {
  try {
    const ctx = getContext();
    if (ctx.state === 'suspended') ctx.resume();

    const t = ctx.currentTime;
    const duration = 0.6;
    
    // Major chord: Root, Major 3rd, Perfect 5th
    const freqs = [523.25, 659.25, 783.99]; // C5, E5, G5

    freqs.forEach((f, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.type = 'sine';
      osc.frequency.value = f;

      const start = t + (i * 0.05);
      gain.gain.setValueAtTime(0, start);
      gain.gain.linearRampToValueAtTime(GAIN_MASTER * 0.5, start + 0.05);
      gain.gain.exponentialRampToValueAtTime(0.001, start + duration);

      osc.start(start);
      osc.stop(start + duration + 0.1);
    });

  } catch {
    // Ignore audio errors
  }
}

/**
 * Play a "compute" sound (random data processing bleeps).
 */
export function playComputeSound() {
  try {
    const ctx = getContext();
    if (ctx.state === 'suspended') ctx.resume();

    const t = ctx.currentTime;
    const count = 5;
    
    for (let i = 0; i < count; i++) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.type = 'square';
      osc.frequency.value = 800 + Math.random() * 1000;
      
      const start = t + (i * 0.06);
      const len = 0.04;

      gain.gain.setValueAtTime(GAIN_MASTER * 0.3, start);
      gain.gain.linearRampToValueAtTime(0.01, start + len);

      osc.start(start);
      osc.stop(start + len);
    }
  } catch {
    // Ignore audio errors
  }
}

/**
 * Play an "error" or "warning" sound (low buzz).
 */
export function playErrorSound() {
  try {
    const ctx = getContext();
    if (ctx.state === 'suspended') ctx.resume();

    const t = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(150, t);
    osc.frequency.linearRampToValueAtTime(100, t + 0.3);

    gain.gain.setValueAtTime(GAIN_MASTER * 0.5, t);
    gain.gain.exponentialRampToValueAtTime(0.01, t + 0.3);

    osc.start(t);
    osc.stop(t + 0.3);
  } catch {
    // Ignore audio errors
  }
}
