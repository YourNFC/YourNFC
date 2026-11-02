/* ===== LIQUID GLASS TILT for YourNFC =====
   Reads the phone's gyroscope and writes smoothed values to CSS variables:
     --tilt-x / --tilt-y  : -1 to 1  (left/right, up/down)
   Falls back to touch/mouse movement when no gyroscope is available.
   Add before </body> on every page that loads the glass CSS:
     <script src="liquid-tilt.js" defer></script>
*/
(function () {
  var root = document.documentElement;
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) return;

  var target = { x: 0, y: 0 };   // where the tilt wants to be
  var current = { x: 0, y: 0 };  // smoothed value (the "liquid" lag)
  var baseline = null;           // resting angle, so holding the phone naturally = centered
  var running = false;

  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

  function onOrientation(e) {
    if (e.gamma == null || e.beta == null) return;
    if (!baseline) baseline = { g: e.gamma, b: e.beta };
    // gamma = left/right (-90..90), beta = front/back (-180..180)
    target.x = clamp((e.gamma - baseline.g) / 30, -1, 1);
    target.y = clamp((e.beta - baseline.b) / 30, -1, 1);
    start();
  }

  // Fallback: finger / mouse position
  function onPointer(e) {
    var p = e.touches ? e.touches[0] : e;
    target.x = (p.clientX / window.innerWidth - 0.5) * 2;
    target.y = (p.clientY / window.innerHeight - 0.5) * 2;
    start();
  }

  function start() {
    if (running) return;
    running = true;
    requestAnimationFrame(tick);
  }

  function tick() {
    // lerp = liquid easing; lower number = more syrupy
    current.x += (target.x - current.x) * 0.08;
    current.y += (target.y - current.y) * 0.08;
    root.style.setProperty('--tilt-x', current.x.toFixed(3));
    root.style.setProperty('--tilt-y', current.y.toFixed(3));
    if (Math.abs(target.x - current.x) > 0.001 || Math.abs(target.y - current.y) > 0.001) {
      requestAnimationFrame(tick);
    } else {
      running = false;
    }
  }

  function listenGyro() {
    window.addEventListener('deviceorientation', onOrientation, true);
  }

  function listenFallback() {
    window.addEventListener('mousemove', onPointer, { passive: true });
    window.addEventListener('touchmove', onPointer, { passive: true });
  }

  // Always keep the fallback so desktop + denied-permission still feel alive
  listenFallback();

  var needsPermission =
    typeof DeviceOrientationEvent !== 'undefined' &&
    typeof DeviceOrientationEvent.requestPermission === 'function'; // iOS 13+

  if (!needsPermission) {
    listenGyro();
    return;
  }

  // iOS requires a user tap to enable motion. Show a small button once.
  var btn = document.createElement('button');
  btn.className = 'btn btn-secondary tilt-enable';
  btn.type = 'button';
  btn.textContent = 'Enable tilt effect';
  btn.addEventListener('click', function () {
    DeviceOrientationEvent.requestPermission()
      .then(function (state) {
        if (state === 'granted') listenGyro();
        btn.remove();
      })
      .catch(function () { btn.remove(); });
  });
  document.body.appendChild(btn);
})();
