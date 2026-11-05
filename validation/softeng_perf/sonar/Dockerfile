# SonarScanner with clang, for cognitive.py --engine sonar.
# The C analyzer (CFamily) runs the compiler named in compile_commands.json to learn its
# predefined macros; the stock scanner image has no compiler, so it skips every file.
FROM sonarsource/sonar-scanner-cli:latest
USER root
RUN dnf install -y clang && dnf clean all
USER scanner-cli
