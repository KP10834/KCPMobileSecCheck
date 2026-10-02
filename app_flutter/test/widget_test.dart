import 'package:app_flutter/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('shows scanner title', (tester) async {
    await tester.pumpWidget(const MobileSecCheckApp());

    expect(find.text('KCP 모바일 보안점검'), findsOneWidget);
  });
}
