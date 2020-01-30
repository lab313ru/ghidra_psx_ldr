package psyq.sym;

public enum SymClass {
	EFCN,
	NULL,
	AUTO,
	EXT,
	STAT,
	REG,
	EXTDEF,
	LABEL,
	ULABEL,
	MOS,
	ARG,
	STRTAG,
	MOU,
	UNTAG,
	TPDEF,
	USTATIC,
	ENTAG,
	MOE,
	REGPARM,
	FIELD,
	BLOCK,
	FCN,
	EOS,
	FILE,
	LINE,
	ALIAS,
	HIDDEN;
	
	public static SymClass fromInt(int value) {
		switch (value) {
		case -1: return SymClass.EFCN;
		case 0: return SymClass.NULL;
		case 1: return SymClass.AUTO;
		case 2: return SymClass.EXT;
		case 3: return SymClass.STAT;
		case 4: return SymClass.REG;
		case 5: return SymClass.EXTDEF;
		case 6: return SymClass.LABEL;
		case 7: return SymClass.ULABEL;
		case 8: return SymClass.MOS;
		case 9: return SymClass.ARG;
		case 10: return SymClass.STRTAG;
		case 11: return SymClass.MOU;
		case 12: return SymClass.UNTAG;
		case 13: return SymClass.TPDEF;
		case 14: return SymClass.USTATIC;
		case 15: return SymClass.ENTAG;
		case 16: return SymClass.MOE;
		case 17: return SymClass.REGPARM;
		case 18: return SymClass.FIELD;
		case 100: return SymClass.BLOCK;
		case 101: return SymClass.FCN;
		case 102: return SymClass.EOS;
		case 103: return SymClass.FILE;
		case 104: return SymClass.LINE;
		case 105: return SymClass.ALIAS;
		case 106: return SymClass.HIDDEN;
		default: return null;
		}
	}
}
