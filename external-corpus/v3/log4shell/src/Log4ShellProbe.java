// Log4ShellProbe — the Log4Shell (CVE-2021-44228) probe.
//
// Reads the first line of the fixture file (the log message) and logs it
// through Log4j 2 with a programmatically configured ConsoleAppender
// (pattern "%m%n", INFO). The fixture contains a JNDI lookup
// ("${jndi:ldap://127.0.0.1:1/a}").
//
//   vulnerable (2.14.1): the lookup is PERFORMED at log time — Log4j
//     attempts an LDAP connection, fails (connection refused), and its
//     StatusLogger emits the "Error looking up JNDI resource" diagnostic.
//   fixed (2.17.1): JNDI lookups are disabled by default — the literal
//     message is logged, no lookup, no diagnostic.
//
// To make the observable independent of where the StatusLogger happens to
// write, the probe registers a StatusListener and CAPTURES the diagnostic,
// then emits a deterministic first line to stdout:
//
//   JNDI_LOOKUP_ATTEMPTED            (vulnerable: a lookup error was seen)
//   JNDI_LOOKUP_NOT_ATTEMPTED        (fixed: no lookup error was seen)
//
// followed (in the vulnerable case) by the captured diagnostic line itself,
// so the residual's first-line divergence carries the historical content.
// Exit is 0 in both cases: the probe itself never fails; the DIVERGENCE is
// the evidence.
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.builder.api.AppenderComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.api.RootLoggerComponentBuilder;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;
import org.apache.logging.log4j.status.StatusData;
import org.apache.logging.log4j.status.StatusListener;
import org.apache.logging.log4j.status.StatusLogger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class Log4ShellProbe {
    /** Captures StatusLogger diagnostics (the JNDI lookup error path). */
    static final class CapturingListener implements StatusListener {
        final List<StatusData> messages = new ArrayList<>();

        @Override
        public void log(StatusData data) {
            messages.add(data);
        }

        @Override
        public Level getStatusLevel() {
            return Level.ALL;
        }

        @Override
        public void close() {
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Log4ShellProbe: usage: Log4ShellProbe FIXTURE");
            System.exit(2);
        }
        String line = Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8)
                .stream()
                .findFirst()
                .orElse("");

        // The DECLARED message-suffix length (spec/reduction.md — the
        // ordered-integer domain projection of the jndi.lookup trigger): if
        // the fixture's first line begins with a `len=N ` directive, the
        // message is the LAST N characters of the line. The minimizer reduces
        // N to the empirical floor at which the lookup trigger still fires
        // (the bare lookup token); one character below — the token without
        // its closing brace — is left literal by the substitutor and the
        // lookup is never attempted. A malformed directive is REFUSED (exit
        // 2), never silently mis-evaluated; a line without a directive is the
        // whole message (the probe remains a general instrument).
        String message = line;
        if (line.startsWith("len=")) {
            int space = line.indexOf(' ');
            int n = -1;
            if (space > 4) {
                try {
                    n = Integer.parseInt(line.substring(4, space));
                } catch (NumberFormatException e) {
                    n = -1;
                }
            }
            if (n < 0) {
                System.err.println("Log4ShellProbe: malformed len= directive in fixture " + args[0]);
                System.exit(2);
            }
            int take = Math.min(n, line.length());
            message = line.substring(line.length() - take);
        }

        CapturingListener capture = new CapturingListener();
        StatusLogger.getLogger().registerListener(capture);

        // A deterministic ConsoleAppender: "%m%n" on STDERR (the log line
        // is identical on both sides; stdout is reserved for the probe's
        // deterministic verdict lines).
        ConfigurationBuilder<BuiltConfiguration> builder =
                ConfigurationBuilderFactory.newConfigurationBuilder();
        builder.setStatusLevel(Level.ERROR);
        builder.setConfigurationName("frf-probe");
        AppenderComponentBuilder console = builder.newAppender("stderr", "Console");
        console.addAttribute("target", ConsoleAppender.Target.SYSTEM_ERR);
        console.add(builder.newLayout("PatternLayout").addAttribute("pattern", "%m%n"));
        builder.add(console);
        RootLoggerComponentBuilder root = builder.newRootLogger(Level.INFO);
        root.add(builder.newAppenderRef("stderr"));
        builder.add(root);
        LoggerContext ctx = Configurator.initialize(builder.build());

        Logger logger = LogManager.getLogger("frf.probe");
        logger.info(message);
        System.out.flush();
        System.err.flush();
        ctx.stop();

        // The observable: did the JNDI lookup error path fire? The verdict
        // is the FIRST stdout line (the built-in first-line comparator's
        // surface). The diagnostic lines that follow carry the historical
        // content WITHOUT timestamps or JVM-specific stack frames, so every
        // emitted line is deterministic.
        StatusData diagnostic = null;
        for (StatusData m : capture.messages) {
            if (m.getMessage().getFormattedMessage()
                    .contains("Error looking up JNDI resource")) {
                diagnostic = m;
                break;
            }
        }
        if (diagnostic != null) {
            System.out.println("JNDI_LOOKUP_ATTEMPTED");
            System.out.println(diagnostic.getMessage().getFormattedMessage());
            Throwable t = diagnostic.getThrowable();
            if (t != null) {
                System.out.println(t.getClass().getName() + ": " + t.getMessage());
            }
        } else {
            System.out.println("JNDI_LOOKUP_NOT_ATTEMPTED");
        }
        System.out.flush();
        System.exit(0);
    }
}
