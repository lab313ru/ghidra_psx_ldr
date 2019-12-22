package psx.debug;

public enum DebuggerGprRegister {
	GPR_R0(0, "r0"),
	GPR_AT(1, "at"),
	
	GPR_V0(2, "v0"),
	GPR_V1(3, "v1"),
	
	GPR_A0(4, "a0"),
	GPR_A1(5, "a1"),
	GPR_A2(6, "a2"),
	GPR_A3(7, "a3"),
	
	GPR_T0(8, "t0"),
	GPR_T1(9, "t1"),
	GPR_T2(10, "t2"),
	GPR_T3(11, "t3"),
	GPR_T4(12, "t4"),
	GPR_T5(13, "t5"),
	GPR_T6(14, "t6"),
	GPR_T7(15, "t7"),
	
	GPR_S0(16, "s0"),
	GPR_S1(17, "s1"),
	GPR_S2(18, "s2"),
	GPR_S3(19, "s3"),
	GPR_S4(20, "s4"),
	GPR_S5(21, "s5"),
	GPR_S6(22, "s6"),
	GPR_S7(23, "s7"),
	
	GPR_T8(24, "t8"),
	GPR_T9(25, "t9"),
	
	GPR_K0(26, "k0"),
	GPR_K1(27, "k1"),
	
	GPR_GP(28, "gp"),
	GPR_SP(29, "sp"),
	
	GPR_S8(30, "s8"),
	
	GPR_RA(31, "ra");
	
	private final int val;
	private final String name;
	
	private DebuggerGprRegister(int val, String name) {
		this.val = val;
		this.name = name;
	}
	
	public int getInt() {
		return val;
	}
	
	public String getName() {
		return name;
	}
}
