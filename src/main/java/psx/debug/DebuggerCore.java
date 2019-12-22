package psx.debug;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DebuggerCore {

	public static final int DEBUG_PORT = 12345;
	private final Socket socket;
	private DataInputStream in = null;
	private DataOutputStream out = null;
	
	public DebuggerCore(String debugHost) throws UnknownHostException, IOException {
		socket = new Socket(debugHost, DEBUG_PORT);
		
		if (socket == null) {
			return;
		}
		
		socket.setSoTimeout(100);
		
		in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
		out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
		System.out.println(readResponse());
	}
	
	private String readResponse() {
		String result = "";
		
		try {
			int b;
			while ((b = in.read()) > 0) {
				result += (char)b;
			}
		} catch (IOException ignored) {
		}
		
		return result.trim();
	}
	
	private void writeRequest(String request) throws IOException {
		request += "\r\n";
		out.writeBytes(request);
		out.flush();
	}
	
	public long getGprRegister(DebuggerGprRegister gpr) throws IOException {
		if (in == null || out == null) {
			return 0L;
		}
		
		DebuggerCmd cmd = DebuggerCmd.CMD_GET_GPR_REG;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt(), gpr.getInt()));
		
		String response = readResponse();
		
		if (response == null || response.isEmpty()) {
			return 0L;
		}
		
		Pattern gprPattern = Pattern.compile(cmd.getRecvFormat());
		Matcher gprMatcher = gprPattern.matcher(response);
		
		if (!gprMatcher.matches()) {
			return 0L;
		}
		
		int regIndex = Integer.parseInt(gprMatcher.group(1));
		String regName = gprMatcher.group(2);
		long regValue = Long.parseLong(gprMatcher.group(3), 16) & 0xFFFFFFFFL;
		
		System.out.println(String.format("Register get \"%s(%d)\"=>%08X", regName, regIndex, regValue));
		
		return regValue;
	}
	
	public long getPcRegister() throws IOException {
		if (in == null || out == null) {
			return 0L;
		}
		
		DebuggerCmd cmd = DebuggerCmd.CMD_GET_PC_REG;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));
		
		String response = readResponse();
		
		if (response == null || response.isEmpty()) {
			return 0L;
		}
		
		Pattern gprPattern = Pattern.compile(cmd.getRecvFormat());
		Matcher gprMatcher = gprPattern.matcher(response);
		
		if (!gprMatcher.matches()) {
			return 0L;
		}
		
		long regValue = Long.parseLong(gprMatcher.group(1), 16) & 0xFFFFFFFFL;
		
		System.out.println(String.format("PC=>%08X", regValue));
		
		return regValue;
	}
	
	public boolean stepInto() throws IOException {
		if (in == null || out == null) {
			return false;
		}
		
		DebuggerCmd cmd = DebuggerCmd.CMD_TRACE_EXECUTION;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));
		
		String response = readResponse();
		
		if (response == null || response.isEmpty()) {
			return false;
		}
		
		String format = cmd.getRecvFormat();
		System.out.println("Step into");
		
		if (format == null) {
			return true;
		}
		
		Pattern gprPattern = Pattern.compile(format);
		Matcher gprMatcher = gprPattern.matcher(response);
		
		if (!gprMatcher.matches()) {
			return false;
		}

		return true;
	}
	
	public boolean stepOver() throws IOException {
		if (in == null || out == null) {
			return false;
		}
		
		DebuggerCmd cmd = DebuggerCmd.CMD_STEP_OVER;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));
		
		String response = readResponse();
		
		if (response == null || response.isEmpty()) {
			return false;
		}
		
		String format = cmd.getRecvFormat();
		System.out.println("Step over");
		
		if (format == null) {
			return true;
		}
		
		Pattern gprPattern = Pattern.compile(format);
		Matcher gprMatcher = gprPattern.matcher(response);
		
		if (!gprMatcher.matches()) {
			return false;
		}
		
		return true;
	}
	
	public boolean runTo() throws IOException {
		if (in == null || out == null) {
			return false;
		}
		
		DebuggerCmd cmd = DebuggerCmd.CMD_RUN_TO;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));
		
		String response = readResponse();
		
		if (response == null || response.isEmpty()) {
			return false;
		}
		
		String format = cmd.getRecvFormat();
		System.out.println("Run to");
		
		if (format == null) {
			return true;
		}
		
		Pattern gprPattern = Pattern.compile(format);
		Matcher gprMatcher = gprPattern.matcher(response);
		
		return gprMatcher.matches();
	}
	
	public boolean pause() throws IOException {
		if (in == null || out == null) {
			return false;
		}
		
		DebuggerCmd cmd = DebuggerCmd.CMD_PAUSE_EXECUTION;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));

		String response = readResponse();
		
		if (response == null || response.isEmpty()) {
			return false;
		}
		
		String format = cmd.getRecvFormat();
		System.out.println("Pause");
		
		if (format == null) {
			return true;
		}
		
		Pattern gprPattern = Pattern.compile(format);
		Matcher gprMatcher = gprPattern.matcher(response);
		
		return gprMatcher.matches();
	}
	
	public boolean resume() throws IOException {
		if (in == null || out == null) {
			return false;
		}
		
		DebuggerCmd cmd = DebuggerCmd.CMD_RESUME_EXECUTION;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));
		
		String response = readResponse();

		if (response == null || response.isEmpty()) {
			return false;
		}
		
		String format = cmd.getRecvFormat();
		System.out.println("Resume");
		
		if (format == null) {
			return true;
		}
		
		Pattern gprPattern = Pattern.compile(format);
		Matcher gprMatcher = gprPattern.matcher(response);
		
		return gprMatcher.matches();
	}
	
	public void closeSocket() throws IOException {
		socket.close();
	}
}
