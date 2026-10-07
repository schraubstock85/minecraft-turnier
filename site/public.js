// Öffentliche Nur-Lesen-Ansicht: Passwort abfragen, data.json laden und im Browser entschlüsseln.
// Der Schlüssel entsteht nur hier aus dem Passwort; im Repo liegt ausschließlich Verschlüsseltes.
"use strict";
window.TURNIER_PUBLIC = true;
(function () {
  const STORE = "turnier-pw";
  let key = null, keySalt = null;

  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  async function deriveKey(pw, salt, iter) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(salt), iterations: iter, hash: "SHA-256" },
                                   base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  }
  async function decryptRaw(box, k) {
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(box.iv) }, k, b64(box.ct));
  }
  async function decrypt(box, k) {
    return JSON.parse(new TextDecoder().decode(await decryptRaw(box, k)));
  }
  // Plakat (mit Namen) liegt ebenfalls verschlüsselt im Repo und wird erst nach dem Entsperren gezeigt
  async function loadPoster(k) {
    try {
      const box = await (await fetch("poster.json")).json();
      const blob = new Blob([await decryptRaw(box, k)], { type: "image/jpeg" });
      document.documentElement.style.setProperty("--poster", "url(" + URL.createObjectURL(blob) + ")");
    } catch (e) { /* ohne Plakat geht es auch */ }
  }
  async function fetchBox() {
    const r = await fetch("data.json?t=" + Date.now(), { cache: "no-store" });
    if (!r.ok) throw new Error("data " + r.status);
    return r.json();
  }

  // Passwort-Maske; Link mit #k=PASSWORT füllt sie automatisch aus
  function askPassword(msg) {
    return new Promise(resolve => {
      const ov = document.getElementById("pwgate");
      const inp = document.getElementById("pwinput");
      document.getElementById("pwmsg").textContent = msg || "";
      ov.style.display = "flex";
      inp.focus();
      document.getElementById("pwform").onsubmit = ev => {
        ev.preventDefault();
        document.getElementById("pwmsg").textContent = "Prüfe …";
        resolve(inp.value.trim());
      };
    });
  }

  async function unlock(box) {
    let pw = null;
    const m = location.hash.match(/k=([^&]+)/);
    if (m) {
      pw = decodeURIComponent(m[1]);
      history.replaceState(null, "", location.pathname);   // Passwort nicht in der Adresszeile stehen lassen
    }
    pw = pw || localStorage.getItem(STORE);
    let msg = "";
    for (;;) {
      if (!pw) pw = await askPassword(msg);
      try {
        const k = await deriveKey(pw, box.salt, box.iter);
        const data = await decrypt(box, k);
        key = k; keySalt = box.salt;
        loadPoster(k);
        localStorage.setItem(STORE, pw);
        document.getElementById("pwgate").style.display = "none";
        return data;
      } catch (e) {
        localStorage.removeItem(STORE);
        pw = null;
        msg = "Falsches Passwort.";
      }
    }
  }

  // Liefert den aktuellen Turnierstand (wird von poll() der Seite aufgerufen)
  let pending = null;   // poll() läuft im Takt weiter, während die Passwort-Maske offen ist
  window.turnierLoad = function () {
    if (pending) return pending;
    pending = (async () => {
      const box = await fetchBox();
      if (!key || box.salt !== keySalt) return unlock(box);
      return decrypt(box, key);
    })();
    pending.then(() => { pending = null; }, () => { pending = null; });
    return pending;
  };
})();
