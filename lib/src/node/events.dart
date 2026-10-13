// Stream view of Node EventEmitter callbacks. Adapters expose error events as
// data (their Node error object carries `.code`) and listening events as a
// void stream; the port keeps subscriptions one-shot and cancels the unused
// listener when either event wins.
abstract interface class NodeEventEmitter {
  Stream<Object?> get errorEvents;
  Stream<void> get listeningEvents;
}
