import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/** jCardSim bridge: one hex APDU per stdin line, one hex response (data || SW) per stdout line. */
public final class Sim {
    public static void main(String[] args) throws Exception {
        CardSimulator sim = new CardSimulator();
        AID aid = AIDUtil.create("F04C4545574F545301");
        // GlobalPlatform-style install parameters: AID length || AID || 0 (privileges) || 0 (params).
        byte[] params = parse("09F04C4545574F545301" + "0000");
        sim.installApplet(aid, lee.wots.WotsApplet.class, params, (short) 0, (byte) params.length);
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            ResponseAPDU r = sim.transmitCommand(new CommandAPDU(parse(line.trim())));
            System.out.println(format(r.getBytes()));
            System.out.flush();
        }
    }

    private static byte[] parse(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }

    private static String format(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }
}
