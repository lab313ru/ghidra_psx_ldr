package psyq.sym;

public enum SymDefClass {
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
	
	public static SymDefClass fromInt(int value) {
		switch (value) {
		case -1: return SymDefClass.EFCN;
		case 0: return SymDefClass.NULL;
		case 1: return SymDefClass.AUTO;
		case 2: return SymDefClass.EXT;
		case 3: return SymDefClass.STAT;
		case 4: return SymDefClass.REG;
		case 5: return SymDefClass.EXTDEF;
		case 6: return SymDefClass.LABEL;
		case 7: return SymDefClass.ULABEL;
		case 8: return SymDefClass.MOS;
		case 9: return SymDefClass.ARG;
		case 10: return SymDefClass.STRTAG;
		case 11: return SymDefClass.MOU;
		case 12: return SymDefClass.UNTAG;
		case 13: return SymDefClass.TPDEF;
		case 14: return SymDefClass.USTATIC;
		case 15: return SymDefClass.ENTAG;
		case 16: return SymDefClass.MOE;
		case 17: return SymDefClass.REGPARM;
		case 18: return SymDefClass.FIELD;
		case 100: return SymDefClass.BLOCK;
		case 101: return SymDefClass.FCN;
		case 102: return SymDefClass.EOS;
		case 103: return SymDefClass.FILE;
		case 104: return SymDefClass.LINE;
		case 105: return SymDefClass.ALIAS;
		case 106: return SymDefClass.HIDDEN;
		default: return null;
		}
	}
}
