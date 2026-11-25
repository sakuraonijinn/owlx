'use strict';
// Minimal default hook: report java.net.URL construction to the control dash.
// Replace this with your own hook scripts; upload them from the NixOS CLI:
//   owlx scripts put myhook.js myhook.js
//   owlx hooks attach 1234 --script myhook.js
send({ type: 'info', message: 'owlx default hook loaded' });

if (Java.available) {
  Java.perform(function () {
    try {
      var URL = Java.use('java.net.URL');
      URL.$init.overload('java.lang.String').implementation = function (value) {
        send({ type: 'url', url: value });
        return this.$init(value);
      };
    } catch (err) {
      send({ type: 'error', message: String(err) });
    }
  });
} else {
  send({ type: 'info', message: 'no Java VM; hook loaded as a no-op' });
}
