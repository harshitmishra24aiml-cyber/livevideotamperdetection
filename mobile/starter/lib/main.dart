import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;

void main() => runApp(const CryptoSentinelApp());

class CryptoSentinelApp extends StatelessWidget {
  const CryptoSentinelApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Crypto Sentinel',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF00C878),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFF07111F),
      ),
      home: const HomeScreen(),
    );
  }
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  static const storage = FlutterSecureStorage();
  final baseUrl = TextEditingController(text: 'https://YOUR-API-HOST');
  final apiKey = TextEditingController();
  PlatformFile? selected;
  String? jobId;
  Map<String, dynamic>? lastResult;
  bool busy = false;
  String status = 'Select a video to create a trusted baseline.';

  @override
  void initState() {
    super.initState();
    storage.read(key: 'api_key').then((value) {
      if (value != null && mounted) apiKey.text = value;
    });
  }

  @override
  void dispose() {
    baseUrl.dispose();
    apiKey.dispose();
    super.dispose();
  }

  Future<void> pickVideo() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['mp4', 'mov', 'avi', 'mkv', 'mpg', 'mpeg'],
    );
    if (result != null && result.files.isNotEmpty) {
      setState(() {
        selected = result.files.single;
        lastResult = null;
        status = 'Selected: ' + selected!.name;
      });
    }
  }

  Uri endpoint(String path) {
    final base = baseUrl.text.trim().replaceAll(RegExp(r'/+$'), '');
    return Uri.parse(base + path);
  }

  Future<Map<String, dynamic>> sendVideo(String path) async {
    if (selected == null || selected!.path == null) {
      throw Exception('Please select a video file first.');
    }
    final request = http.MultipartRequest('POST', endpoint(path));
    request.headers['X-API-Key'] = apiKey.text.trim();
    request.files.add(await http.MultipartFile.fromPath('video', selected!.path!));
    final streamed = await request.send().timeout(const Duration(minutes: 10));
    final response = await http.Response.fromStream(streamed);
    final dynamic decoded = jsonDecode(response.body);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final message = decoded is Map ? decoded['detail'] ?? response.body : response.body;
      throw Exception(message.toString());
    }
    if (decoded is! Map<String, dynamic>) {
      throw Exception('Unexpected response from API.');
    }
    return decoded;
  }

  Future<void> createBaseline() async {
    if (apiKey.text.trim().isEmpty) {
      showMessage('Enter the API key provided by the backend administrator.');
      return;
    }
    if (!baseUrl.text.startsWith('https://') && !baseUrl.text.startsWith('http://')) {
      showMessage('Enter a valid API base URL, including https://');
      return;
    }
    setState(() { busy = true; status = 'Uploading and hashing video frames...'; });
    try {
      await storage.write(key: 'api_key', value: apiKey.text.trim());
      final result = await sendVideo('/api/v1/videos/analyze');
      setState(() {
        jobId = result['job_id']?.toString();
        lastResult = result;
        status = 'Baseline created. Keep the Job ID for later verification.';
      });
    } catch (error) {
      setState(() => status = 'Error: ' + error.toString());
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> verifyAgainstBaseline() async {
    if (jobId == null) {
      showMessage('Create a baseline first.');
      return;
    }
    setState(() { busy = true; status = 'Comparing uploaded frames with baseline...'; });
    try {
      final result = await sendVideo('/api/v1/jobs/' + jobId! + '/verify');
      final comparison = result['comparison'] as Map<String, dynamic>? ?? {};
      setState(() {
        lastResult = result;
        status = comparison['is_match'] == true
            ? 'MATCH: frames match the stored baseline.'
            : 'ALERT: differences found against the stored baseline.';
      });
    } catch (error) {
      setState(() => status = 'Error: ' + error.toString());
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  void showMessage(String value) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(value)));
  }

  @override
  Widget build(BuildContext context) {
    final comparison = lastResult?['comparison'] as Map<String, dynamic>?;
    final metadata = lastResult?['metadata'] as Map<String, dynamic>?;
    return Scaffold(
      appBar: AppBar(
        title: const Row(children: [
          Icon(Icons.shield_outlined, color: Color(0xFF00D084)),
          SizedBox(width: 10),
          Text('Crypto Sentinel', style: TextStyle(fontWeight: FontWeight.bold)),
        ]),
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(18),
          children: [
            const Text('Video Integrity Monitor',
              style: TextStyle(fontSize: 25, fontWeight: FontWeight.bold)),
            const SizedBox(height: 6),
            Text('SHA-256 frame hashing • Tamper verification',
              style: TextStyle(color: Colors.blueGrey.shade200)),
            const SizedBox(height: 18),
            Card(child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Text('Backend connection', style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
                const SizedBox(height: 12),
                TextField(
                  controller: baseUrl,
                  keyboardType: TextInputType.url,
                  decoration: const InputDecoration(labelText: 'API base URL', border: OutlineInputBorder()),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: apiKey,
                  obscureText: true,
                  decoration: const InputDecoration(labelText: 'API key', border: OutlineInputBorder()),
                ),
              ]),
            )),
            const SizedBox(height: 14),
            Card(child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Text('1. Select a video', style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
                const SizedBox(height: 12),
                OutlinedButton.icon(
                  onPressed: busy ? null : pickVideo,
                  icon: const Icon(Icons.video_file_outlined),
                  label: const Text('Choose video from phone'),
                ),
                if (selected != null) ...[
                  const SizedBox(height: 8),
                  Text(selected!.name, maxLines: 2, overflow: TextOverflow.ellipsis),
                  Text((selected!.size / (1024 * 1024)).toStringAsFixed(2) + ' MB',
                    style: TextStyle(color: Colors.blueGrey.shade200)),
                ],
                const SizedBox(height: 16),
                const Text('2. Create original reference', style: TextStyle(fontWeight: FontWeight.w600)),
                const SizedBox(height: 8),
                SizedBox(width: double.infinity, child: FilledButton.icon(
                  onPressed: busy || selected == null ? null : createBaseline,
                  icon: const Icon(Icons.lock_outline),
                  label: const Text('Upload & create SHA-256 baseline'),
                )),
                const SizedBox(height: 16),
                const Text('3. Verify a later copy', style: TextStyle(fontWeight: FontWeight.w600)),
                const SizedBox(height: 8),
                SizedBox(width: double.infinity, child: OutlinedButton.icon(
                  onPressed: busy || selected == null || jobId == null ? null : verifyAgainstBaseline,
                  icon: const Icon(Icons.verified_user_outlined),
                  label: const Text('Compare against saved baseline'),
                )),
              ]),
            )),
            if (busy) ...[
              const SizedBox(height: 16),
              const LinearProgressIndicator(),
            ],
            const SizedBox(height: 16),
            Card(child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Text('Status', style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
                const SizedBox(height: 8),
                Text(status),
                if (jobId != null) ...[
                  const SizedBox(height: 8),
                  SelectableText('Job ID: ' + jobId!),
                ],
                if (metadata != null) ...[
                  const Divider(height: 24),
                  Text('Frames hashed: ' + (metadata['processed_frame_count'] ?? '-').toString()),
                  Text('Source SHA-256: ' + (metadata['source_file_sha256'] ?? '-').toString()),
                ],
                if (comparison != null) ...[
                  const Divider(height: 24),
                  Text('Integrity: ' + (comparison['integrity_percent'] ?? 0).toString() + '%'),
                  Text('Frames checked: ' + (comparison['frames_checked'] ?? 0).toString()),
                  Text('Mismatches: ' + (comparison['mismatch_count'] ?? 0).toString()),
                  if (comparison['mismatches'] is List)
                    ...((comparison['mismatches'] as List).take(20).map(
                      (item) => Text('Frame ' + item['frame'].toString() + ': ' + item['status'].toString()),
                    )),
                ],
              ]),
            )),
            const SizedBox(height: 16),
            Text(
              'Forensic note: the first upload creates the reference baseline. It cannot prove the video was authentic before that first upload. Protect the baseline and signing authority.',
              style: TextStyle(color: Colors.amber.shade200, fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }
}
