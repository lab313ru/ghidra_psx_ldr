package psx.debug;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DebuggerCore {

	public static final int DEBUG_PORT = 12345;
	private final AsynchronousSocketChannel client;
	
	public DebuggerCore(String debugHost) throws InterruptedException, ExecutionException, IOException {
		client = AsynchronousSocketChannel.open();
		InetSocketAddress hostAddress = new InetSocketAddress(debugHost, DEBUG_PORT);
		Future<Void> future = client.connect(hostAddress);
		
		future.get();
		
		readResponse(this::printToConsole);
	}
	
	private String printToConsole(String line) {
		System.out.println(line);
		return null;
	}
	
	@SuppressWarnings("unchecked")
	private void readResponse(Function<String, String> fn) {
		CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
			ByteBuffer buffer = ByteBuffer.allocate(256); 
			try {
				client.read(buffer).get();
			} catch (InterruptedException | ExecutionException e) {
				return null;
			}
			return new String(buffer.array()).trim();
		});
		
		future.thenApplyAsync(res -> fn.apply(res));
	}
	
	private void writeRequest(String request) throws InterruptedException, ExecutionException {
		request += "\r\n";
		ByteBuffer buffer = ByteBuffer.wrap(request.getBytes());
		Future<Integer> write = client.write(buffer);
		write.get();
	}
	
	public long getGprRegister(DebuggerGprRegister gpr, Function<String, String> callback) throws InterruptedException, ExecutionException {
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
		
		// int regIndex = Integer.parseInt(gprMatcher.group(1), 16);
		// String regName = gprMatcher.group(2);
		long regValue = Long.parseLong(gprMatcher.group(3), 16) & 0xFFFFFFFFL;
		
		// System.out.println(String.format("Register get \"%s(%d)\"=>%08X", regName, regIndex, regValue));
		
		return regValue;
	}
	
	public long getPcRegister() throws InterruptedException, ExecutionException {
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
		
		// System.out.println(String.format("PC=>%08X", regValue));
		
		return regValue;
	}
	
	public long[] getLoHiRegisters() throws InterruptedException, ExecutionException {
		DebuggerCmd cmd = DebuggerCmd.CMD_GET_LO_HI_REGS;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));
		
		String response = readResponse();
		
		if (response == null || response.isEmpty()) {
			return new long[] {0L, 0L};
		}
		
		Pattern gprPattern = Pattern.compile(cmd.getRecvFormat());
		Matcher gprMatcher = gprPattern.matcher(response);
		
		if (!gprMatcher.matches()) {
			return new long[] {0L, 0L};
		}
		
		long loValue = Long.parseLong(gprMatcher.group(1), 16) & 0xFFFFFFFFL;
		long hiValue = Long.parseLong(gprMatcher.group(2), 16) & 0xFFFFFFFFL;
		
		// System.out.println(String.format("LO=>%08X, HI=>%08X", loValue, hiValue));
		
		return new long[] {loValue, hiValue};
	}
	
	public boolean stepInto() throws InterruptedException, ExecutionException {
		DebuggerCmd cmd = DebuggerCmd.CMD_TRACE_EXECUTION;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));
		
		String response = readResponse();

		return !(response == null || response.isEmpty());
	}
	
	public boolean stepOver() throws InterruptedException, ExecutionException {
		DebuggerCmd cmd = DebuggerCmd.CMD_STEP_OVER;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));
		
		String response = readResponse();

		return !(response == null || response.isEmpty());
	}
	
	public boolean runTo() throws InterruptedException, ExecutionException {
		DebuggerCmd cmd = DebuggerCmd.CMD_RUN_TO;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));
		
		String response = readResponse();

		return !(response == null || response.isEmpty());
	}
	
	public boolean pause() throws InterruptedException, ExecutionException {
		DebuggerCmd cmd = DebuggerCmd.CMD_PAUSE_EXECUTION;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));

		String response = readResponse();

		return !(response == null || response.isEmpty());
	}
	
	public boolean resume() throws InterruptedException, ExecutionException {
		DebuggerCmd cmd = DebuggerCmd.CMD_RESUME_EXECUTION;
		writeRequest(String.format(cmd.getSendFormat(), cmd.getInt()));
		
		String response = readResponse();

		return !(response == null || response.isEmpty());
	}
	
	public void closeSocket() throws IOException {
		client.close();
	}
	
	@FunctionalInterface
	public interface AcceptString {
	 
	    void apply(String result);
	 
	}
}
