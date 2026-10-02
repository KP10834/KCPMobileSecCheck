import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() {
  runApp(const MobileSecCheckApp());
}

class MobileSecCheckApp extends StatelessWidget {
  const MobileSecCheckApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'KCP Mobile Security Check',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF2563EB)),
        useMaterial3: true,
      ),
      home: const ScanPage(),
    );
  }
}

class ScanPage extends StatefulWidget {
  const ScanPage({super.key});

  @override
  State<ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends State<ScanPage> {
  static const _dropChannel = MethodChannel('kcp_mobile_sec_check/drop');

  final _pathController = TextEditingController();
  String _status = 'IPA, APK, AAB 파일을 드래그하거나 선택하세요.';
  bool _running = false;
  bool _dragging = false;

  @override
  void initState() {
    super.initState();
    _dropChannel.setMethodCallHandler((call) async {
      if (call.method == 'dragEntered') {
        setState(() => _dragging = true);
      } else if (call.method == 'dragExited') {
        setState(() => _dragging = false);
      } else if (call.method == 'fileDropped') {
        final path = call.arguments as String?;
        if (path == null) return;
        _pathController.text = path;
        setState(() {
          _dragging = false;
          _status = '파일 선택됨: ${File(path).uri.pathSegments.last}';
        });
        await _scan();
      }
    });
  }

  @override
  void dispose() {
    _pathController.dispose();
    super.dispose();
  }

  Future<void> _scan() async {
    final target = _pathController.text.trim();
    if (target.isEmpty) {
      setState(() => _status = '파일 경로가 비어 있습니다.');
      return;
    }

    final file = File(target);
    if (!file.existsSync()) {
      setState(() => _status = '파일을 찾을 수 없습니다.');
      return;
    }

    final suffix = target.split('.').last.toLowerCase();
    if (!{'ipa', 'apk', 'aab'}.contains(suffix)) {
      setState(() => _status = '지원 형식은 ipa, apk, aab 입니다.');
      return;
    }

    setState(() {
      _running = true;
      _status = '점검 중...';
    });

    final projectDir = Directory('/Users/user/src/KCPMobileSecCheck');
    final timestamp = _timestamp();
    final outDir = Directory('/Users/user/KCP보안점검/${file.uri.pathSegments.last}_$timestamp');

    final result = await Process.run(
      'python3',
      [
        '${projectDir.path}/mobile_sec_check.py',
        'scan',
        target,
        '--out',
        outDir.path,
      ],
      workingDirectory: projectDir.path,
    );

    if (!mounted) return;

    if (result.exitCode == 0) {
      final packageName = await _packageName(outDir, file);
      final report = '/Users/user/KCP보안점검/${packageName}_$timestamp.html';
      await File('${outDir.path}/report.html').copy(report);
      await Process.run('open', [report]);
      setState(() => _status = '완료: $report');
    } else {
      setState(() => _status = '실패: ${result.stdout}${result.stderr}');
    }

    setState(() => _running = false);
  }

  String _timestamp() {
    final now = DateTime.now();
    String two(int value) => value.toString().padLeft(2, '0');
    return '${now.year}${two(now.month)}${two(now.day)}T${two(now.hour)}${two(now.minute)}${two(now.second)}';
  }

  Future<String> _packageName(Directory outDir, File file) async {
    try {
      final jsonText = await File('${outDir.path}/report.json').readAsString();
      final data = jsonDecode(jsonText) as Map<String, dynamic>;
      final package = data['package']?.toString();
      if (package != null && package.isNotEmpty && package != '-') return package;
    } catch (_) {
      // keep filename fallback
    }
    return file.uri.pathSegments.last.replaceAll(RegExp(r'[^0-9A-Za-z._-]'), '_');
  }

  Future<void> _chooseFile() async {
    final result = await Process.run('osascript', [
      '-e',
      'POSIX path of (choose file of type {"ipa", "apk", "aab"} with prompt "점검할 앱 파일을 선택하세요")',
    ]);
    if (!mounted || result.exitCode != 0) return;
    _pathController.text = result.stdout.toString().trim();
    await _scan();
  }

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;

    return Scaffold(
      backgroundColor: const Color(0xFFF4F7FA),
      body: SafeArea(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 900),
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    Container(
                      width: 44,
                      height: 44,
                      decoration: BoxDecoration(
                        color: colors.primary,
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: const Icon(Icons.security, color: Colors.white),
                    ),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Text(
                        'KCP 모바일 보안점검',
                        style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                              fontWeight: FontWeight.w800,
                            ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 28),
                Expanded(
                  child: AnimatedContainer(
                    duration: const Duration(milliseconds: 160),
                    decoration: BoxDecoration(
                      color: _dragging ? const Color(0xFFEAF2FF) : Colors.white,
                      borderRadius: BorderRadius.circular(18),
                      border: Border.all(
                        color: _dragging ? colors.primary : const Color(0xFFD7DEE8),
                        width: _dragging ? 2 : 1,
                      ),
                      boxShadow: const [
                        BoxShadow(
                          color: Color(0x140F172A),
                          blurRadius: 28,
                          offset: Offset(0, 16),
                        ),
                      ],
                    ),
                    child: Center(
                      child: Padding(
                        padding: const EdgeInsets.all(28),
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.file_upload_outlined,
                              size: 76,
                              color: _dragging ? colors.primary : const Color(0xFF64748B),
                            ),
                            const SizedBox(height: 18),
                            Text(
                              _dragging ? '여기에 놓으면 바로 점검합니다' : 'IPA / APK / AAB 파일을 여기에 드래그',
                              textAlign: TextAlign.center,
                              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                                    fontWeight: FontWeight.w800,
                                  ),
                            ),
                            const SizedBox(height: 10),
                            Text(
                              'AppGuard 적용 산출물도 그대로 넣으면 됩니다.',
                              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                                    color: const Color(0xFF64748B),
                                  ),
                            ),
                            const SizedBox(height: 24),
                            FilledButton.icon(
                              onPressed: _running ? null : _chooseFile,
                              icon: const Icon(Icons.folder_open),
                              label: Text(_running ? '점검 중...' : '파일 선택'),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 18),
                TextField(
                  controller: _pathController,
                  decoration: const InputDecoration(
                    filled: true,
                    fillColor: Colors.white,
                    border: OutlineInputBorder(borderRadius: BorderRadius.all(Radius.circular(12))),
                    labelText: 'IPA / APK / AAB 경로',
                    hintText: '/Users/user/.../KCPWallet-appguard.aab',
                  ),
                  onSubmitted: (_) => _running ? null : _scan(),
                ),
                const SizedBox(height: 12),
                SelectableText(_status),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
