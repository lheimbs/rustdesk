import 'package:fake_async/fake_async.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_test/flutter_test.dart';

class _FakeFFI implements FFI {
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  test('every state the controlled side reports is shown, granted counts down',
      () {
    fakeAsync((async) {
      final model = ElevationModel(WeakReference(_FakeFFI()));
      model.onStatus(ElevationState.requested.index, 0);
      expect(model.state.value, ElevationState.requested);
      expect(model.showDropMenu, isFalse);

      model.onStatus(ElevationState.granted.index, 90);
      expect(model.state.value, ElevationState.granted);
      expect(model.showDropMenu, isTrue);
      async.elapse(const Duration(seconds: 30));
      expect(model.secondsLeft.value, 60);

      for (final end in [
        ElevationState.denied,
        ElevationState.expired,
        ElevationState.revoked,
        ElevationState.none
      ]) {
        model.onStatus(ElevationState.granted.index, 90);
        model.onStatus(end.index, 0);
        expect(model.state.value, end);
        expect(model.secondsLeft.value, 0);
        expect(model.showDropMenu, isFalse);
      }
      async.elapse(const Duration(seconds: 120));
      expect(model.secondsLeft.value, 0);

      model.onStatus(99, 0);
      expect(model.state.value, ElevationState.none);
    });
  });
}
