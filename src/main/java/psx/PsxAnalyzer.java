package psx;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import psyq.SigApplier;


public class PsxAnalyzer extends AbstractAnalyzer {
	private Map<String, SigApplier> appliers;
	
	private boolean sequential = true;
	private boolean onlyFirst = false;
	private String manualVer = "4.7";
	
	private final String SEQ_OPTION = "Sequential search";
	private final String FIRST_OPTION = "Only first match";
	private final String MANUAL_VER_OPTION = "PsyQ Version if not found";
	
	public static boolean isPsxLoader(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(PsxLoader.PSX_LOADER);
	}
	
	public PsxAnalyzer() {
		super("PsyQ Signatures", "PSX signatures applier", AnalyzerType.INSTRUCTION_ANALYZER);
		
		setSupportsOneTimeAnalysis();
		
		appliers = new HashMap<>();
	}
	
	@Override
	public boolean getDefaultEnablement(Program program) {
		return isPsxLoader(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return isPsxLoader(program);
	}
	
	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(SEQ_OPTION, sequential, null, "To decrease false positive signatures matching use LIBrary's OBJects order.");
		options.registerOption(FIRST_OPTION, onlyFirst, null, "To increase signatures applying time set this option CHECKED. Applies only first entry!");
		options.registerOption(MANUAL_VER_OPTION, manualVer, null, "Use this version number if not found in the binary.");
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		
		sequential = options.getBoolean(SEQ_OPTION, sequential);
		onlyFirst = options.getBoolean(FIRST_OPTION, onlyFirst);
		manualVer = options.getString(MANUAL_VER_OPTION, manualVer);
		
		appliers = new HashMap<>();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		try {
			String psyqVersion = PsxLoader.getProgramPsyqVersion(program);
			
			AddressRangeIterator i = set.getAddressRanges();
			
			while (i.hasNext()) {
				AddressRange next = i.next();
				
				if (psyqVersion.isEmpty() && !manualVer.isEmpty()) {
					psyqVersion = manualVer.replace(".", "");
				}
				
				applyPsyqSignaturesByVersion(psyqVersion, program, next.getMinAddress(), next.getMaxAddress(), monitor, log);
			}
			
			monitor.setMessage("Applying PsyQ functions and data types...");
			monitor.clearCanceled();
			
			PsxLoader.loadPsyqGdt(program, set);
			
			monitor.setMessage("Applying PsyQ functions and data types done.");
		} catch (IOException e) {
			e.printStackTrace();
			log.appendException(e);
			return false;
		}
		
		return true;
	}
	
	private void applyPsyqSignaturesByVersion(final String version, Program program, final Address startAddr, final Address endAddr, TaskMonitor monitor, MessageLog log) throws IOException {
		final String psyDir = String.format("psyq/%s", version);
		final File verDir = Application.getModuleDataSubDirectory(psyDir).getFile(false);
		
		File [] files = verDir.listFiles(new FilenameFilter() {
		    @Override
		    public boolean accept(File dir, String name) {
		        return name.endsWith(".json");
		    }
		});
		
		for (var file : files) {
			final String fileName = file.getName();
			SigApplier sig;
			
			if (appliers.containsKey(fileName)) {
				sig = appliers.get(fileName);
			} else {
				sig = new SigApplier(file.getAbsolutePath(), sequential, onlyFirst, monitor);
				appliers.put(fileName, sig);
			}
			
			sig.applySignatures(program, startAddr, endAddr, monitor, log);
		}
	}
}
