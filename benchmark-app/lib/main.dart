// Intentionally unsafe FlutterGuard benchmark input. Local testing only.
//
// The values below are synthetic. They have no account behind them, the host
// is reserved (.invalid), and this app performs no network operation.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;

// Provider-shaped on purpose; deliberately not a valid credential.
const String benchmarkApiKey =
    'sk-proj-benchmarkFAKE4f8c2a91d7e6b350c9d1e7a2b6f80345';

// Supplied on the build command line: --dart-define=FG_BENCHMARK_SECRET=...
const String benchmarkDefine = String.fromEnvironment(
  'FG_BENCHMARK_SECRET',
  defaultValue: 'FG_BENCHMARK_DEFINE_UNSET',
);

const String benchmarkEnvAsset = 'assets/test.env';

void main() => runApp(const BenchmarkApp());

class BenchmarkApp extends StatelessWidget {
  const BenchmarkApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'FlutterGuard Benchmark (UNSAFE)',
      home: FixtureScreen(),
    );
  }
}

class FixtureScreen extends StatefulWidget {
  const FixtureScreen({super.key});

  @override
  State<FixtureScreen> createState() => _FixtureScreenState();
}

class _FixtureScreenState extends State<FixtureScreen> {
  String _env = 'assets/test.env not loaded';

  @override
  void initState() {
    super.initState();
    rootBundle.loadString('assets/test.env').then((String value) {
      if (mounted) setState(() => _env = value);
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('UNSAFE benchmark fixture')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Text(
            'Synthetic inputs for local scanner evaluation. Not for distribution.',
          ),
          const SizedBox(height: 12),
          _FactRow(label: 'Provider-shaped API key', value: benchmarkApiKey),
          _FactRow(
            label: 'dart-define FG_BENCHMARK_SECRET',
            value: benchmarkDefine,
          ),
          _FactRow(label: 'Asset $benchmarkEnvAsset', value: _env),
        ],
      ),
    );
  }
}

class _FactRow extends StatelessWidget {
  const _FactRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 4),
          SelectableText(value),
        ],
      ),
    );
  }
}
