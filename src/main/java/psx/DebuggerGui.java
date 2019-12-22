package psx;

import javax.swing.JPanel;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import javax.swing.JLabel;
import javax.swing.JTabbedPane;
import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.JSeparator;
import javax.swing.SwingConstants;
import javax.swing.border.TitledBorder;
import java.awt.Color;
import javax.swing.border.LineBorder;

public class DebuggerGui extends JPanel {
	private JTextField edtPc;
	private JTextField edtLo;
	private JTextField edtHi;
	private JTextField edtR0;
	private JTextField edtAt;
	private JTextField edtV0;
	private JTextField edtV1;
	private JTextField edtA0;
	private JTextField edtA1;
	private JTextField edtA2;
	private JTextField edtA3;
	private JTextField edtT0;
	private JTextField edtT1;
	private JTextField edtS0;
	private JTextField edtS1;
	private JTextField edtS2;
	private JTextField edtS3;
	private JTextField edtS4;
	private JTextField edtS5;
	private JTextField edtS6;
	private JTextField edtS7;
	private JTextField edtS8;
	private JTextField edtK0;
	private JTextField edtK1;
	private JTextField edtT2;
	private JTextField edtT3;
	private JTextField edtT4;
	private JTextField edtT5;
	private JTextField edtT6;
	private JTextField edtT7;
	private JTextField edtT8;
	private JTextField edtT9;
	private JTextField edtGp;
	private JTextField edtSp;
	private JTextField edtRa;
	private JTextField textField_35;
	private JTextField textField_36;
	private JTextField textField_37;
	private JTextField textField_38;
	private JTextField textField_39;
	private JTextField textField_40;
	private JTextField textField_41;
	private JTextField textField_42;
	private JTextField textField_43;
	private JTextField textField_44;
	private JTextField textField_45;
	private JTextField textField_46;
	private JTextField textField_47;
	private JTextField textField_48;
	private JTextField textField_49;
	private JTextField textField_50;
	private JTextField textField_51;
	private JTextField textField_52;
	private JTextField textField_53;
	private JTextField textField_54;
	private JTextField textField_55;
	private JTextField textField_56;
	private JTextField textField_57;
	private JTextField textField_58;
	private JTextField textField_59;
	private JTextField textField_60;
	private JTextField textField_61;
	private JTextField textField_62;
	private JTextField textField_63;
	private JTextField textField_64;
	private JTextField textField_65;
	private JTextField textField_66;
	private JTextField textField_67;
	private JTextField textField_68;
	private JTextField textField_69;
	private JTextField textField_70;
	private JTextField textField_71;
	private JTextField textField_72;
	private JTextField textField_73;
	private JTextField textField_74;
	private JTextField textField_75;
	private JTextField textField_76;
	private JTextField textField_77;
	private JTextField textField_78;
	private JTextField textField_79;
	private JTextField textField_80;
	private JTextField textField_81;
	private JTextField textField_82;
	private JTextField textField_83;
	private JTextField textField_84;
	private JTextField textField_85;
	private JTextField textField_86;
	private JTextField textField_87;
	private JTextField textField_88;
	private JTextField textField_89;
	private JTextField textField_90;
	private JTextField textField_91;
	private JTextField textField_92;
	private JTextField textField_93;
	private JTextField textField_94;
	private JTextField textField_95;
	private JTextField textField_96;
	private JTextField textField_97;
	private JTextField textField_98;
	private JTextField textField_99;
	private JTextField textField_100;
	private JTextField textField_101;
	private JTextField textField_102;
	private JTextField textField_103;
	private JTextField textField_104;
	private JTextField textField_105;
	private JTextField textField_106;
	private JTextField textField_107;
	private JTextField textField_108;
	private JTextField textField_109;
	private JTextField textField_110;
	private JTextField textField_111;
	private JTextField textField_112;
	private JTextField textField_113;
	private JTextField textField_114;
	private JTextField textField_115;
	private JTextField textField_116;
	private JTextField textField_117;
	private JTextField textField_118;
	private JTextField textField_119;
	private JTextField textField_120;
	private JTextField textField_121;
	private JTextField textField_122;
	private JTextField textField_123;
	private JTextField textField_124;
	private JTextField textField_125;
	private JTextField textField_126;
	private JTextField textField_127;

	/**
	 * Create the panel.
	 */
	public DebuggerGui() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{123, 248, 0};
		gridBagLayout.rowHeights = new int[]{0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);
		
		JPanel pnlCpuCtrl = new JPanel();
		pnlCpuCtrl.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 1, true), "CPU Control", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagConstraints gbc_pnlCpuCtrl = new GridBagConstraints();
		gbc_pnlCpuCtrl.fill = GridBagConstraints.HORIZONTAL;
		gbc_pnlCpuCtrl.anchor = GridBagConstraints.NORTH;
		gbc_pnlCpuCtrl.insets = new Insets(0, 0, 0, 5);
		gbc_pnlCpuCtrl.gridx = 0;
		gbc_pnlCpuCtrl.gridy = 0;
		add(pnlCpuCtrl, gbc_pnlCpuCtrl);
		GridBagLayout gbl_pnlCpuCtrl = new GridBagLayout();
		gbl_pnlCpuCtrl.columnWidths = new int[]{107, 0};
		gbl_pnlCpuCtrl.rowHeights = new int[]{0, 0, 0, 0, 0};
		gbl_pnlCpuCtrl.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_pnlCpuCtrl.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		pnlCpuCtrl.setLayout(gbl_pnlCpuCtrl);
		
		JButton btnStepInto = new JButton("Step Into");
		GridBagConstraints gbc_btnStepInto = new GridBagConstraints();
		gbc_btnStepInto.insets = new Insets(0, 0, 5, 0);
		gbc_btnStepInto.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnStepInto.gridx = 0;
		gbc_btnStepInto.gridy = 0;
		pnlCpuCtrl.add(btnStepInto, gbc_btnStepInto);
		
		JButton btnStepOver = new JButton("Step Over");
		GridBagConstraints gbc_btnStepOver = new GridBagConstraints();
		gbc_btnStepOver.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnStepOver.insets = new Insets(0, 0, 5, 0);
		gbc_btnStepOver.gridx = 0;
		gbc_btnStepOver.gridy = 1;
		pnlCpuCtrl.add(btnStepOver, gbc_btnStepOver);
		
		JButton btnPause = new JButton("Pause");
		GridBagConstraints gbc_btnPause = new GridBagConstraints();
		gbc_btnPause.insets = new Insets(0, 0, 5, 0);
		gbc_btnPause.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnPause.gridx = 0;
		gbc_btnPause.gridy = 2;
		pnlCpuCtrl.add(btnPause, gbc_btnPause);
		
		JButton btnRun = new JButton("Run");
		GridBagConstraints gbc_btnRun = new GridBagConstraints();
		gbc_btnRun.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnRun.gridx = 0;
		gbc_btnRun.gridy = 3;
		pnlCpuCtrl.add(btnRun, gbc_btnRun);
		
		JTabbedPane tbbRegs = new JTabbedPane(SwingConstants.TOP);
		GridBagConstraints gbc_tbbRegs = new GridBagConstraints();
		gbc_tbbRegs.fill = GridBagConstraints.BOTH;
		gbc_tbbRegs.gridx = 1;
		gbc_tbbRegs.gridy = 0;
		add(tbbRegs, gbc_tbbRegs);
		
		JPanel pnlGprRegs = new JPanel();
		tbbRegs.addTab("GPR", null, pnlGprRegs, null);
		GridBagLayout gbl_pnlGprRegs = new GridBagLayout();
		gbl_pnlGprRegs.columnWidths = new int[]{143, 0};
		gbl_pnlGprRegs.rowHeights = new int[]{560, 0};
		gbl_pnlGprRegs.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_pnlGprRegs.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		pnlGprRegs.setLayout(gbl_pnlGprRegs);
		
		JPanel pnlGprRegs1 = new JPanel();
		GridBagConstraints gbc_pnlGprRegs1 = new GridBagConstraints();
		gbc_pnlGprRegs1.fill = GridBagConstraints.BOTH;
		gbc_pnlGprRegs1.gridx = 0;
		gbc_pnlGprRegs1.gridy = 0;
		pnlGprRegs.add(pnlGprRegs1, gbc_pnlGprRegs1);
		GridBagLayout gbl_pnlGprRegs1 = new GridBagLayout();
		gbl_pnlGprRegs1.columnWidths = new int[]{0, 134, 17, 0, 145, 0};
		gbl_pnlGprRegs1.rowHeights = new int[]{0, 0, 25, 0, 0, 25, 0, 0, 0, 25, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_pnlGprRegs1.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gbl_pnlGprRegs1.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		pnlGprRegs1.setLayout(gbl_pnlGprRegs1);
		
		JLabel lbR0 = new JLabel("$r0");
		GridBagConstraints gbc_lbR0 = new GridBagConstraints();
		gbc_lbR0.insets = new Insets(0, 0, 5, 5);
		gbc_lbR0.anchor = GridBagConstraints.EAST;
		gbc_lbR0.gridx = 0;
		gbc_lbR0.gridy = 0;
		pnlGprRegs1.add(lbR0, gbc_lbR0);
		
		edtR0 = new JTextField();
		lbR0.setLabelFor(edtR0);
		GridBagConstraints gbc_edtR0 = new GridBagConstraints();
		gbc_edtR0.insets = new Insets(0, 0, 5, 5);
		gbc_edtR0.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtR0.gridx = 1;
		gbc_edtR0.gridy = 0;
		pnlGprRegs1.add(edtR0, gbc_edtR0);
		edtR0.setColumns(10);
		
		JSeparator sep0 = new JSeparator();
		sep0.setOrientation(SwingConstants.VERTICAL);
		GridBagConstraints gbc_sep0 = new GridBagConstraints();
		gbc_sep0.fill = GridBagConstraints.VERTICAL;
		gbc_sep0.gridheight = 21;
		gbc_sep0.insets = new Insets(0, 0, 0, 5);
		gbc_sep0.gridx = 2;
		gbc_sep0.gridy = 0;
		pnlGprRegs1.add(sep0, gbc_sep0);
		
		JLabel lbS0 = new JLabel("$s0");
		GridBagConstraints gbc_lbS0 = new GridBagConstraints();
		gbc_lbS0.anchor = GridBagConstraints.EAST;
		gbc_lbS0.insets = new Insets(0, 0, 5, 5);
		gbc_lbS0.gridx = 3;
		gbc_lbS0.gridy = 0;
		pnlGprRegs1.add(lbS0, gbc_lbS0);
		
		edtS0 = new JTextField();
		lbS0.setLabelFor(edtS0);
		GridBagConstraints gbc_edtS0 = new GridBagConstraints();
		gbc_edtS0.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtS0.insets = new Insets(0, 0, 5, 0);
		gbc_edtS0.gridx = 4;
		gbc_edtS0.gridy = 0;
		pnlGprRegs1.add(edtS0, gbc_edtS0);
		edtS0.setColumns(10);
		
		JLabel lbAt = new JLabel("$at");
		GridBagConstraints gbc_lbAt = new GridBagConstraints();
		gbc_lbAt.anchor = GridBagConstraints.EAST;
		gbc_lbAt.insets = new Insets(0, 0, 5, 5);
		gbc_lbAt.gridx = 0;
		gbc_lbAt.gridy = 1;
		pnlGprRegs1.add(lbAt, gbc_lbAt);
		
		edtAt = new JTextField();
		lbAt.setLabelFor(edtAt);
		GridBagConstraints gbc_edtAt = new GridBagConstraints();
		gbc_edtAt.insets = new Insets(0, 0, 5, 5);
		gbc_edtAt.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtAt.gridx = 1;
		gbc_edtAt.gridy = 1;
		pnlGprRegs1.add(edtAt, gbc_edtAt);
		edtAt.setColumns(10);
		
		JLabel lbS1 = new JLabel("$s1");
		GridBagConstraints gbc_lbS1 = new GridBagConstraints();
		gbc_lbS1.anchor = GridBagConstraints.EAST;
		gbc_lbS1.insets = new Insets(0, 0, 5, 5);
		gbc_lbS1.gridx = 3;
		gbc_lbS1.gridy = 1;
		pnlGprRegs1.add(lbS1, gbc_lbS1);
		
		edtS1 = new JTextField();
		lbS1.setLabelFor(edtS1);
		GridBagConstraints gbc_edtS1 = new GridBagConstraints();
		gbc_edtS1.insets = new Insets(0, 0, 5, 0);
		gbc_edtS1.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtS1.gridx = 4;
		gbc_edtS1.gridy = 1;
		pnlGprRegs1.add(edtS1, gbc_edtS1);
		edtS1.setColumns(10);
		
		JSeparator sep1 = new JSeparator();
		GridBagConstraints gbc_sep1 = new GridBagConstraints();
		gbc_sep1.gridwidth = 2;
		gbc_sep1.fill = GridBagConstraints.HORIZONTAL;
		gbc_sep1.insets = new Insets(0, 0, 5, 5);
		gbc_sep1.gridx = 0;
		gbc_sep1.gridy = 2;
		pnlGprRegs1.add(sep1, gbc_sep1);
		
		JLabel lbS2 = new JLabel("$s2");
		GridBagConstraints gbc_lbS2 = new GridBagConstraints();
		gbc_lbS2.anchor = GridBagConstraints.EAST;
		gbc_lbS2.insets = new Insets(0, 0, 5, 5);
		gbc_lbS2.gridx = 3;
		gbc_lbS2.gridy = 2;
		pnlGprRegs1.add(lbS2, gbc_lbS2);
		
		edtS2 = new JTextField();
		lbS2.setLabelFor(edtS2);
		GridBagConstraints gbc_edtS2 = new GridBagConstraints();
		gbc_edtS2.insets = new Insets(0, 0, 5, 0);
		gbc_edtS2.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtS2.gridx = 4;
		gbc_edtS2.gridy = 2;
		pnlGprRegs1.add(edtS2, gbc_edtS2);
		edtS2.setColumns(10);
		
		JLabel lbV0 = new JLabel("$v0");
		GridBagConstraints gbc_lbV0 = new GridBagConstraints();
		gbc_lbV0.anchor = GridBagConstraints.EAST;
		gbc_lbV0.insets = new Insets(0, 0, 5, 5);
		gbc_lbV0.gridx = 0;
		gbc_lbV0.gridy = 3;
		pnlGprRegs1.add(lbV0, gbc_lbV0);
		
		edtV0 = new JTextField();
		lbV0.setLabelFor(edtV0);
		GridBagConstraints gbc_edtV0 = new GridBagConstraints();
		gbc_edtV0.insets = new Insets(0, 0, 5, 5);
		gbc_edtV0.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtV0.gridx = 1;
		gbc_edtV0.gridy = 3;
		pnlGprRegs1.add(edtV0, gbc_edtV0);
		edtV0.setColumns(10);
		
		JLabel lbS3 = new JLabel("$s3");
		GridBagConstraints gbc_lbS3 = new GridBagConstraints();
		gbc_lbS3.anchor = GridBagConstraints.EAST;
		gbc_lbS3.insets = new Insets(0, 0, 5, 5);
		gbc_lbS3.gridx = 3;
		gbc_lbS3.gridy = 3;
		pnlGprRegs1.add(lbS3, gbc_lbS3);
		
		edtS3 = new JTextField();
		lbS3.setLabelFor(edtS3);
		GridBagConstraints gbc_edtS3 = new GridBagConstraints();
		gbc_edtS3.insets = new Insets(0, 0, 5, 0);
		gbc_edtS3.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtS3.gridx = 4;
		gbc_edtS3.gridy = 3;
		pnlGprRegs1.add(edtS3, gbc_edtS3);
		edtS3.setColumns(10);
		
		JLabel lbV1 = new JLabel("$v1");
		GridBagConstraints gbc_lbV1 = new GridBagConstraints();
		gbc_lbV1.anchor = GridBagConstraints.EAST;
		gbc_lbV1.insets = new Insets(0, 0, 5, 5);
		gbc_lbV1.gridx = 0;
		gbc_lbV1.gridy = 4;
		pnlGprRegs1.add(lbV1, gbc_lbV1);
		
		edtV1 = new JTextField();
		lbV1.setLabelFor(edtV1);
		GridBagConstraints gbc_edtV1 = new GridBagConstraints();
		gbc_edtV1.insets = new Insets(0, 0, 5, 5);
		gbc_edtV1.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtV1.gridx = 1;
		gbc_edtV1.gridy = 4;
		pnlGprRegs1.add(edtV1, gbc_edtV1);
		edtV1.setColumns(10);
		
		JLabel lbS4 = new JLabel("$s4");
		GridBagConstraints gbc_lbS4 = new GridBagConstraints();
		gbc_lbS4.anchor = GridBagConstraints.EAST;
		gbc_lbS4.insets = new Insets(0, 0, 5, 5);
		gbc_lbS4.gridx = 3;
		gbc_lbS4.gridy = 4;
		pnlGprRegs1.add(lbS4, gbc_lbS4);
		
		edtS4 = new JTextField();
		lbS4.setLabelFor(edtS4);
		GridBagConstraints gbc_edtS4 = new GridBagConstraints();
		gbc_edtS4.insets = new Insets(0, 0, 5, 0);
		gbc_edtS4.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtS4.gridx = 4;
		gbc_edtS4.gridy = 4;
		pnlGprRegs1.add(edtS4, gbc_edtS4);
		edtS4.setColumns(10);
		
		JSeparator sep2 = new JSeparator();
		GridBagConstraints gbc_sep2 = new GridBagConstraints();
		gbc_sep2.fill = GridBagConstraints.HORIZONTAL;
		gbc_sep2.gridwidth = 2;
		gbc_sep2.insets = new Insets(0, 0, 5, 5);
		gbc_sep2.gridx = 0;
		gbc_sep2.gridy = 5;
		pnlGprRegs1.add(sep2, gbc_sep2);
		
		JLabel lbS5 = new JLabel("$s5");
		GridBagConstraints gbc_lbS5 = new GridBagConstraints();
		gbc_lbS5.anchor = GridBagConstraints.EAST;
		gbc_lbS5.insets = new Insets(0, 0, 5, 5);
		gbc_lbS5.gridx = 3;
		gbc_lbS5.gridy = 5;
		pnlGprRegs1.add(lbS5, gbc_lbS5);
		
		edtS5 = new JTextField();
		lbS5.setLabelFor(edtS5);
		GridBagConstraints gbc_edtS5 = new GridBagConstraints();
		gbc_edtS5.insets = new Insets(0, 0, 5, 0);
		gbc_edtS5.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtS5.gridx = 4;
		gbc_edtS5.gridy = 5;
		pnlGprRegs1.add(edtS5, gbc_edtS5);
		edtS5.setColumns(10);
		
		JLabel lbA0 = new JLabel("$a0");
		GridBagConstraints gbc_lbA0 = new GridBagConstraints();
		gbc_lbA0.anchor = GridBagConstraints.EAST;
		gbc_lbA0.insets = new Insets(0, 0, 5, 5);
		gbc_lbA0.gridx = 0;
		gbc_lbA0.gridy = 6;
		pnlGprRegs1.add(lbA0, gbc_lbA0);
		
		edtA0 = new JTextField();
		lbA0.setLabelFor(edtA0);
		GridBagConstraints gbc_edtA0 = new GridBagConstraints();
		gbc_edtA0.insets = new Insets(0, 0, 5, 5);
		gbc_edtA0.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtA0.gridx = 1;
		gbc_edtA0.gridy = 6;
		pnlGprRegs1.add(edtA0, gbc_edtA0);
		edtA0.setColumns(10);
		
		JLabel lbS6 = new JLabel("$s6");
		GridBagConstraints gbc_lbS6 = new GridBagConstraints();
		gbc_lbS6.anchor = GridBagConstraints.EAST;
		gbc_lbS6.insets = new Insets(0, 0, 5, 5);
		gbc_lbS6.gridx = 3;
		gbc_lbS6.gridy = 6;
		pnlGprRegs1.add(lbS6, gbc_lbS6);
		
		edtS6 = new JTextField();
		lbS6.setLabelFor(edtS6);
		GridBagConstraints gbc_edtS6 = new GridBagConstraints();
		gbc_edtS6.insets = new Insets(0, 0, 5, 0);
		gbc_edtS6.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtS6.gridx = 4;
		gbc_edtS6.gridy = 6;
		pnlGprRegs1.add(edtS6, gbc_edtS6);
		edtS6.setColumns(10);
		
		JLabel lbA1 = new JLabel("$a1");
		GridBagConstraints gbc_lbA1 = new GridBagConstraints();
		gbc_lbA1.anchor = GridBagConstraints.EAST;
		gbc_lbA1.insets = new Insets(0, 0, 5, 5);
		gbc_lbA1.gridx = 0;
		gbc_lbA1.gridy = 7;
		pnlGprRegs1.add(lbA1, gbc_lbA1);
		
		edtA1 = new JTextField();
		lbA1.setLabelFor(edtA1);
		GridBagConstraints gbc_edtA1 = new GridBagConstraints();
		gbc_edtA1.insets = new Insets(0, 0, 5, 5);
		gbc_edtA1.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtA1.gridx = 1;
		gbc_edtA1.gridy = 7;
		pnlGprRegs1.add(edtA1, gbc_edtA1);
		edtA1.setColumns(10);
		
		JLabel lbS7 = new JLabel("$s7");
		GridBagConstraints gbc_lbS7 = new GridBagConstraints();
		gbc_lbS7.anchor = GridBagConstraints.EAST;
		gbc_lbS7.insets = new Insets(0, 0, 5, 5);
		gbc_lbS7.gridx = 3;
		gbc_lbS7.gridy = 7;
		pnlGprRegs1.add(lbS7, gbc_lbS7);
		
		edtS7 = new JTextField();
		lbS7.setLabelFor(edtS7);
		GridBagConstraints gbc_edtS7 = new GridBagConstraints();
		gbc_edtS7.insets = new Insets(0, 0, 5, 0);
		gbc_edtS7.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtS7.gridx = 4;
		gbc_edtS7.gridy = 7;
		pnlGprRegs1.add(edtS7, gbc_edtS7);
		edtS7.setColumns(10);
		
		JLabel lbA2 = new JLabel("$a2");
		GridBagConstraints gbc_lbA2 = new GridBagConstraints();
		gbc_lbA2.anchor = GridBagConstraints.EAST;
		gbc_lbA2.insets = new Insets(0, 0, 5, 5);
		gbc_lbA2.gridx = 0;
		gbc_lbA2.gridy = 8;
		pnlGprRegs1.add(lbA2, gbc_lbA2);
		
		edtA2 = new JTextField();
		lbA2.setLabelFor(edtA2);
		GridBagConstraints gbc_edtA2 = new GridBagConstraints();
		gbc_edtA2.insets = new Insets(0, 0, 5, 5);
		gbc_edtA2.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtA2.gridx = 1;
		gbc_edtA2.gridy = 8;
		pnlGprRegs1.add(edtA2, gbc_edtA2);
		edtA2.setColumns(10);
		
		JLabel lbS8 = new JLabel("$s8");
		GridBagConstraints gbc_lbS8 = new GridBagConstraints();
		gbc_lbS8.anchor = GridBagConstraints.EAST;
		gbc_lbS8.insets = new Insets(0, 0, 5, 5);
		gbc_lbS8.gridx = 3;
		gbc_lbS8.gridy = 8;
		pnlGprRegs1.add(lbS8, gbc_lbS8);
		
		edtS8 = new JTextField();
		lbS8.setLabelFor(edtS8);
		GridBagConstraints gbc_edtS8 = new GridBagConstraints();
		gbc_edtS8.insets = new Insets(0, 0, 5, 0);
		gbc_edtS8.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtS8.gridx = 4;
		gbc_edtS8.gridy = 8;
		pnlGprRegs1.add(edtS8, gbc_edtS8);
		edtS8.setColumns(10);
		
		JLabel lbA3 = new JLabel("$a3");
		GridBagConstraints gbc_lbA3 = new GridBagConstraints();
		gbc_lbA3.anchor = GridBagConstraints.EAST;
		gbc_lbA3.insets = new Insets(0, 0, 5, 5);
		gbc_lbA3.gridx = 0;
		gbc_lbA3.gridy = 9;
		pnlGprRegs1.add(lbA3, gbc_lbA3);
		
		edtA3 = new JTextField();
		lbA3.setLabelFor(edtA3);
		GridBagConstraints gbc_edtA3 = new GridBagConstraints();
		gbc_edtA3.insets = new Insets(0, 0, 5, 5);
		gbc_edtA3.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtA3.gridx = 1;
		gbc_edtA3.gridy = 9;
		pnlGprRegs1.add(edtA3, gbc_edtA3);
		edtA3.setColumns(10);
		
		JSeparator sep4 = new JSeparator();
		GridBagConstraints gbc_sep4 = new GridBagConstraints();
		gbc_sep4.gridwidth = 2;
		gbc_sep4.fill = GridBagConstraints.HORIZONTAL;
		gbc_sep4.insets = new Insets(0, 0, 5, 0);
		gbc_sep4.gridx = 3;
		gbc_sep4.gridy = 9;
		pnlGprRegs1.add(sep4, gbc_sep4);
		
		JSeparator sep5 = new JSeparator();
		GridBagConstraints gbc_sep5 = new GridBagConstraints();
		gbc_sep5.insets = new Insets(0, 0, 5, 5);
		gbc_sep5.fill = GridBagConstraints.HORIZONTAL;
		gbc_sep5.gridwidth = 2;
		gbc_sep5.gridx = 0;
		gbc_sep5.gridy = 10;
		pnlGprRegs1.add(sep5, gbc_sep5);
		
		JLabel lbK0 = new JLabel("$k0");
		GridBagConstraints gbc_lbK0 = new GridBagConstraints();
		gbc_lbK0.anchor = GridBagConstraints.EAST;
		gbc_lbK0.insets = new Insets(0, 0, 5, 5);
		gbc_lbK0.gridx = 3;
		gbc_lbK0.gridy = 10;
		pnlGprRegs1.add(lbK0, gbc_lbK0);
		
		edtK0 = new JTextField();
		lbK0.setLabelFor(edtK0);
		GridBagConstraints gbc_edtK0 = new GridBagConstraints();
		gbc_edtK0.insets = new Insets(0, 0, 5, 0);
		gbc_edtK0.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtK0.gridx = 4;
		gbc_edtK0.gridy = 10;
		pnlGprRegs1.add(edtK0, gbc_edtK0);
		edtK0.setColumns(10);
		
		JLabel lbT0 = new JLabel("$t0");
		GridBagConstraints gbc_lbT0 = new GridBagConstraints();
		gbc_lbT0.anchor = GridBagConstraints.EAST;
		gbc_lbT0.insets = new Insets(0, 0, 5, 5);
		gbc_lbT0.gridx = 0;
		gbc_lbT0.gridy = 11;
		pnlGprRegs1.add(lbT0, gbc_lbT0);
		
		edtT0 = new JTextField();
		lbT0.setLabelFor(edtT0);
		GridBagConstraints gbc_edtT0 = new GridBagConstraints();
		gbc_edtT0.insets = new Insets(0, 0, 5, 5);
		gbc_edtT0.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtT0.gridx = 1;
		gbc_edtT0.gridy = 11;
		pnlGprRegs1.add(edtT0, gbc_edtT0);
		edtT0.setColumns(10);
		
		JLabel lbK1 = new JLabel("$k1");
		GridBagConstraints gbc_lbK1 = new GridBagConstraints();
		gbc_lbK1.anchor = GridBagConstraints.EAST;
		gbc_lbK1.insets = new Insets(0, 0, 5, 5);
		gbc_lbK1.gridx = 3;
		gbc_lbK1.gridy = 11;
		pnlGprRegs1.add(lbK1, gbc_lbK1);
		
		edtK1 = new JTextField();
		lbK1.setLabelFor(edtK1);
		GridBagConstraints gbc_edtK1 = new GridBagConstraints();
		gbc_edtK1.insets = new Insets(0, 0, 5, 0);
		gbc_edtK1.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtK1.gridx = 4;
		gbc_edtK1.gridy = 11;
		pnlGprRegs1.add(edtK1, gbc_edtK1);
		edtK1.setColumns(10);
		
		JLabel lbT1 = new JLabel("$t1");
		GridBagConstraints gbc_lbT1 = new GridBagConstraints();
		gbc_lbT1.anchor = GridBagConstraints.EAST;
		gbc_lbT1.insets = new Insets(0, 0, 5, 5);
		gbc_lbT1.gridx = 0;
		gbc_lbT1.gridy = 12;
		pnlGprRegs1.add(lbT1, gbc_lbT1);
		
		edtT1 = new JTextField();
		lbT1.setLabelFor(edtT1);
		GridBagConstraints gbc_edtT1 = new GridBagConstraints();
		gbc_edtT1.insets = new Insets(0, 0, 5, 5);
		gbc_edtT1.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtT1.gridx = 1;
		gbc_edtT1.gridy = 12;
		pnlGprRegs1.add(edtT1, gbc_edtT1);
		edtT1.setColumns(10);
		
		JSeparator sep6 = new JSeparator();
		GridBagConstraints gbc_sep6 = new GridBagConstraints();
		gbc_sep6.fill = GridBagConstraints.HORIZONTAL;
		gbc_sep6.gridwidth = 2;
		gbc_sep6.insets = new Insets(0, 0, 5, 0);
		gbc_sep6.gridx = 3;
		gbc_sep6.gridy = 12;
		pnlGprRegs1.add(sep6, gbc_sep6);
		
		JLabel lbT2 = new JLabel("$t2");
		GridBagConstraints gbc_lbT2 = new GridBagConstraints();
		gbc_lbT2.anchor = GridBagConstraints.EAST;
		gbc_lbT2.insets = new Insets(0, 0, 5, 5);
		gbc_lbT2.gridx = 0;
		gbc_lbT2.gridy = 13;
		pnlGprRegs1.add(lbT2, gbc_lbT2);
		
		edtT2 = new JTextField();
		lbT2.setLabelFor(edtT2);
		GridBagConstraints gbc_edtT2 = new GridBagConstraints();
		gbc_edtT2.insets = new Insets(0, 0, 5, 5);
		gbc_edtT2.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtT2.gridx = 1;
		gbc_edtT2.gridy = 13;
		pnlGprRegs1.add(edtT2, gbc_edtT2);
		edtT2.setColumns(10);
		
		JPanel panel = new JPanel();
		panel.setBorder(new LineBorder(new Color(0, 0, 0), 1, true));
		GridBagConstraints gbc_panel = new GridBagConstraints();
		gbc_panel.fill = GridBagConstraints.BOTH;
		gbc_panel.gridheight = 2;
		gbc_panel.gridwidth = 2;
		gbc_panel.insets = new Insets(0, 0, 5, 0);
		gbc_panel.gridx = 3;
		gbc_panel.gridy = 13;
		pnlGprRegs1.add(panel, gbc_panel);
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{0, 145, 0};
		gbl_panel.rowHeights = new int[]{0, 0, 0};
		gbl_panel.columnWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		panel.setLayout(gbl_panel);
		
		JLabel lbGp = new JLabel("$gp");
		GridBagConstraints gbc_lbGp = new GridBagConstraints();
		gbc_lbGp.anchor = GridBagConstraints.EAST;
		gbc_lbGp.insets = new Insets(0, 0, 5, 5);
		gbc_lbGp.gridx = 0;
		gbc_lbGp.gridy = 0;
		panel.add(lbGp, gbc_lbGp);
		
		edtGp = new JTextField();
		lbGp.setLabelFor(edtGp);
		GridBagConstraints gbc_edtGp = new GridBagConstraints();
		gbc_edtGp.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtGp.insets = new Insets(0, 0, 5, 0);
		gbc_edtGp.gridx = 1;
		gbc_edtGp.gridy = 0;
		panel.add(edtGp, gbc_edtGp);
		edtGp.setColumns(10);
		
		JLabel lbSp = new JLabel("$sp");
		GridBagConstraints gbc_lbSp = new GridBagConstraints();
		gbc_lbSp.anchor = GridBagConstraints.EAST;
		gbc_lbSp.insets = new Insets(0, 0, 0, 5);
		gbc_lbSp.gridx = 0;
		gbc_lbSp.gridy = 1;
		panel.add(lbSp, gbc_lbSp);
		
		edtSp = new JTextField();
		lbSp.setLabelFor(edtSp);
		GridBagConstraints gbc_edtSp = new GridBagConstraints();
		gbc_edtSp.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtSp.gridx = 1;
		gbc_edtSp.gridy = 1;
		panel.add(edtSp, gbc_edtSp);
		edtSp.setColumns(10);
		
		JLabel lbT3 = new JLabel("$t3");
		GridBagConstraints gbc_lbT3 = new GridBagConstraints();
		gbc_lbT3.anchor = GridBagConstraints.EAST;
		gbc_lbT3.insets = new Insets(0, 0, 5, 5);
		gbc_lbT3.gridx = 0;
		gbc_lbT3.gridy = 14;
		pnlGprRegs1.add(lbT3, gbc_lbT3);
		
		edtT3 = new JTextField();
		lbT3.setLabelFor(edtT3);
		GridBagConstraints gbc_edtT3 = new GridBagConstraints();
		gbc_edtT3.insets = new Insets(0, 0, 5, 5);
		gbc_edtT3.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtT3.gridx = 1;
		gbc_edtT3.gridy = 14;
		pnlGprRegs1.add(edtT3, gbc_edtT3);
		edtT3.setColumns(10);
		
		JLabel lbT4 = new JLabel("$t4");
		GridBagConstraints gbc_lbT4 = new GridBagConstraints();
		gbc_lbT4.anchor = GridBagConstraints.EAST;
		gbc_lbT4.insets = new Insets(0, 0, 5, 5);
		gbc_lbT4.gridx = 0;
		gbc_lbT4.gridy = 15;
		pnlGprRegs1.add(lbT4, gbc_lbT4);
		
		edtT4 = new JTextField();
		lbT4.setLabelFor(edtT4);
		GridBagConstraints gbc_edtT4 = new GridBagConstraints();
		gbc_edtT4.insets = new Insets(0, 0, 5, 5);
		gbc_edtT4.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtT4.gridx = 1;
		gbc_edtT4.gridy = 15;
		pnlGprRegs1.add(edtT4, gbc_edtT4);
		edtT4.setColumns(10);
		
		JSeparator sep7 = new JSeparator();
		GridBagConstraints gbc_sep7 = new GridBagConstraints();
		gbc_sep7.fill = GridBagConstraints.HORIZONTAL;
		gbc_sep7.gridwidth = 2;
		gbc_sep7.insets = new Insets(0, 0, 5, 0);
		gbc_sep7.gridx = 3;
		gbc_sep7.gridy = 15;
		pnlGprRegs1.add(sep7, gbc_sep7);
		
		JLabel lbT5 = new JLabel("$t5");
		GridBagConstraints gbc_lbT5 = new GridBagConstraints();
		gbc_lbT5.anchor = GridBagConstraints.EAST;
		gbc_lbT5.insets = new Insets(0, 0, 5, 5);
		gbc_lbT5.gridx = 0;
		gbc_lbT5.gridy = 16;
		pnlGprRegs1.add(lbT5, gbc_lbT5);
		
		edtT5 = new JTextField();
		lbT5.setLabelFor(edtT5);
		GridBagConstraints gbc_edtT5 = new GridBagConstraints();
		gbc_edtT5.insets = new Insets(0, 0, 5, 5);
		gbc_edtT5.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtT5.gridx = 1;
		gbc_edtT5.gridy = 16;
		pnlGprRegs1.add(edtT5, gbc_edtT5);
		edtT5.setColumns(10);
		
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new LineBorder(new Color(0, 0, 0), 1, true));
		GridBagConstraints gbc_panel_1 = new GridBagConstraints();
		gbc_panel_1.fill = GridBagConstraints.BOTH;
		gbc_panel_1.gridheight = 2;
		gbc_panel_1.gridwidth = 2;
		gbc_panel_1.insets = new Insets(0, 0, 5, 5);
		gbc_panel_1.gridx = 3;
		gbc_panel_1.gridy = 16;
		pnlGprRegs1.add(panel_1, gbc_panel_1);
		GridBagLayout gbl_panel_1 = new GridBagLayout();
		gbl_panel_1.columnWidths = new int[]{0, 145, 0};
		gbl_panel_1.rowHeights = new int[]{0, 0, 0};
		gbl_panel_1.columnWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		gbl_panel_1.rowWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		panel_1.setLayout(gbl_panel_1);
		
		JLabel lbPc = new JLabel("$pc");
		GridBagConstraints gbc_lbPc = new GridBagConstraints();
		gbc_lbPc.anchor = GridBagConstraints.EAST;
		gbc_lbPc.insets = new Insets(0, 0, 5, 5);
		gbc_lbPc.gridx = 0;
		gbc_lbPc.gridy = 0;
		panel_1.add(lbPc, gbc_lbPc);
		
		edtPc = new JTextField();
		lbPc.setLabelFor(edtPc);
		GridBagConstraints gbc_edtPc = new GridBagConstraints();
		gbc_edtPc.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtPc.insets = new Insets(0, 0, 5, 0);
		gbc_edtPc.gridx = 1;
		gbc_edtPc.gridy = 0;
		panel_1.add(edtPc, gbc_edtPc);
		edtPc.setColumns(10);
		
		JLabel lbRa = new JLabel("$ra");
		GridBagConstraints gbc_lbRa = new GridBagConstraints();
		gbc_lbRa.anchor = GridBagConstraints.EAST;
		gbc_lbRa.insets = new Insets(0, 0, 0, 5);
		gbc_lbRa.gridx = 0;
		gbc_lbRa.gridy = 1;
		panel_1.add(lbRa, gbc_lbRa);
		
		edtRa = new JTextField();
		lbRa.setLabelFor(edtRa);
		GridBagConstraints gbc_edtRa = new GridBagConstraints();
		gbc_edtRa.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtRa.gridx = 1;
		gbc_edtRa.gridy = 1;
		panel_1.add(edtRa, gbc_edtRa);
		edtRa.setColumns(10);
		
		JLabel lbT6 = new JLabel("$t6");
		GridBagConstraints gbc_lbT6 = new GridBagConstraints();
		gbc_lbT6.anchor = GridBagConstraints.EAST;
		gbc_lbT6.insets = new Insets(0, 0, 5, 5);
		gbc_lbT6.gridx = 0;
		gbc_lbT6.gridy = 17;
		pnlGprRegs1.add(lbT6, gbc_lbT6);
		
		edtT6 = new JTextField();
		lbT6.setLabelFor(edtT6);
		GridBagConstraints gbc_edtT6 = new GridBagConstraints();
		gbc_edtT6.insets = new Insets(0, 0, 5, 5);
		gbc_edtT6.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtT6.gridx = 1;
		gbc_edtT6.gridy = 17;
		pnlGprRegs1.add(edtT6, gbc_edtT6);
		edtT6.setColumns(10);
		
		JLabel lbT7 = new JLabel("$t7");
		GridBagConstraints gbc_lbT7 = new GridBagConstraints();
		gbc_lbT7.anchor = GridBagConstraints.EAST;
		gbc_lbT7.insets = new Insets(0, 0, 5, 5);
		gbc_lbT7.gridx = 0;
		gbc_lbT7.gridy = 18;
		pnlGprRegs1.add(lbT7, gbc_lbT7);
		
		edtT7 = new JTextField();
		lbT7.setLabelFor(edtT7);
		GridBagConstraints gbc_edtT7 = new GridBagConstraints();
		gbc_edtT7.insets = new Insets(0, 0, 5, 5);
		gbc_edtT7.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtT7.gridx = 1;
		gbc_edtT7.gridy = 18;
		pnlGprRegs1.add(edtT7, gbc_edtT7);
		edtT7.setColumns(10);
		
		JSeparator sep8 = new JSeparator();
		GridBagConstraints gbc_sep8 = new GridBagConstraints();
		gbc_sep8.fill = GridBagConstraints.HORIZONTAL;
		gbc_sep8.gridwidth = 2;
		gbc_sep8.insets = new Insets(0, 0, 5, 0);
		gbc_sep8.gridx = 3;
		gbc_sep8.gridy = 18;
		pnlGprRegs1.add(sep8, gbc_sep8);
		
		JLabel lbT8 = new JLabel("$t8");
		GridBagConstraints gbc_lbT8 = new GridBagConstraints();
		gbc_lbT8.anchor = GridBagConstraints.EAST;
		gbc_lbT8.insets = new Insets(0, 0, 5, 5);
		gbc_lbT8.gridx = 0;
		gbc_lbT8.gridy = 19;
		pnlGprRegs1.add(lbT8, gbc_lbT8);
		
		edtT8 = new JTextField();
		lbT8.setLabelFor(edtT8);
		GridBagConstraints gbc_edtT8 = new GridBagConstraints();
		gbc_edtT8.insets = new Insets(0, 0, 5, 5);
		gbc_edtT8.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtT8.gridx = 1;
		gbc_edtT8.gridy = 19;
		pnlGprRegs1.add(edtT8, gbc_edtT8);
		edtT8.setColumns(10);
		
		JLabel lbLo = new JLabel("$Lo");
		GridBagConstraints gbc_lbLo = new GridBagConstraints();
		gbc_lbLo.anchor = GridBagConstraints.EAST;
		gbc_lbLo.insets = new Insets(0, 0, 5, 5);
		gbc_lbLo.gridx = 3;
		gbc_lbLo.gridy = 19;
		pnlGprRegs1.add(lbLo, gbc_lbLo);
		
		edtLo = new JTextField();
		lbLo.setLabelFor(edtLo);
		GridBagConstraints gbc_edtLo = new GridBagConstraints();
		gbc_edtLo.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtLo.insets = new Insets(0, 0, 5, 0);
		gbc_edtLo.gridx = 4;
		gbc_edtLo.gridy = 19;
		pnlGprRegs1.add(edtLo, gbc_edtLo);
		edtLo.setColumns(10);
		
		JLabel lbT9 = new JLabel("$t9");
		GridBagConstraints gbc_lbT9 = new GridBagConstraints();
		gbc_lbT9.anchor = GridBagConstraints.EAST;
		gbc_lbT9.insets = new Insets(0, 0, 0, 5);
		gbc_lbT9.gridx = 0;
		gbc_lbT9.gridy = 20;
		pnlGprRegs1.add(lbT9, gbc_lbT9);
		
		edtT9 = new JTextField();
		lbT9.setLabelFor(edtT9);
		GridBagConstraints gbc_edtT9 = new GridBagConstraints();
		gbc_edtT9.insets = new Insets(0, 0, 0, 5);
		gbc_edtT9.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtT9.gridx = 1;
		gbc_edtT9.gridy = 20;
		pnlGprRegs1.add(edtT9, gbc_edtT9);
		edtT9.setColumns(10);
		
		JLabel lbHi = new JLabel("$Hi");
		GridBagConstraints gbc_lbHi = new GridBagConstraints();
		gbc_lbHi.anchor = GridBagConstraints.EAST;
		gbc_lbHi.insets = new Insets(0, 0, 0, 5);
		gbc_lbHi.gridx = 3;
		gbc_lbHi.gridy = 20;
		pnlGprRegs1.add(lbHi, gbc_lbHi);
		
		edtHi = new JTextField();
		lbHi.setLabelFor(edtHi);
		GridBagConstraints gbc_edtHi = new GridBagConstraints();
		gbc_edtHi.fill = GridBagConstraints.HORIZONTAL;
		gbc_edtHi.gridx = 4;
		gbc_edtHi.gridy = 20;
		pnlGprRegs1.add(edtHi, gbc_edtHi);
		edtHi.setColumns(10);
		
		JPanel pnlCop0Regs = new JPanel();
		tbbRegs.addTab("COP0", null, pnlCop0Regs, null);
		GridBagLayout gbl_pnlCop0Regs = new GridBagLayout();
		gbl_pnlCop0Regs.columnWidths = new int[]{375, 0};
		gbl_pnlCop0Regs.rowHeights = new int[]{512, 0};
		gbl_pnlCop0Regs.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_pnlCop0Regs.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		pnlCop0Regs.setLayout(gbl_pnlCop0Regs);
		
		JPanel pnlCop0Regs1 = new JPanel();
		GridBagConstraints gbc_pnlCop0Regs1 = new GridBagConstraints();
		gbc_pnlCop0Regs1.fill = GridBagConstraints.BOTH;
		gbc_pnlCop0Regs1.gridx = 0;
		gbc_pnlCop0Regs1.gridy = 0;
		pnlCop0Regs.add(pnlCop0Regs1, gbc_pnlCop0Regs1);
		GridBagLayout gbl_pnlCop0Regs1 = new GridBagLayout();
		gbl_pnlCop0Regs1.columnWidths = new int[]{0, 135, 0, 135, 0};
		gbl_pnlCop0Regs1.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_pnlCop0Regs1.columnWeights = new double[]{0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_pnlCop0Regs1.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		pnlCop0Regs1.setLayout(gbl_pnlCop0Regs1);
		
		JLabel lblIndex = new JLabel("Index");
		GridBagConstraints gbc_lblIndex = new GridBagConstraints();
		gbc_lblIndex.anchor = GridBagConstraints.EAST;
		gbc_lblIndex.insets = new Insets(0, 0, 5, 5);
		gbc_lblIndex.gridx = 0;
		gbc_lblIndex.gridy = 0;
		pnlCop0Regs1.add(lblIndex, gbc_lblIndex);
		
		textField_35 = new JTextField();
		GridBagConstraints gbc_textField_35 = new GridBagConstraints();
		gbc_textField_35.insets = new Insets(0, 0, 5, 5);
		gbc_textField_35.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_35.gridx = 1;
		gbc_textField_35.gridy = 0;
		pnlCop0Regs1.add(textField_35, gbc_textField_35);
		textField_35.setColumns(10);
		
		JLabel lblConfig = new JLabel("Config");
		GridBagConstraints gbc_lblConfig = new GridBagConstraints();
		gbc_lblConfig.anchor = GridBagConstraints.EAST;
		gbc_lblConfig.insets = new Insets(0, 0, 5, 5);
		gbc_lblConfig.gridx = 2;
		gbc_lblConfig.gridy = 0;
		pnlCop0Regs1.add(lblConfig, gbc_lblConfig);
		
		textField_36 = new JTextField();
		GridBagConstraints gbc_textField_36 = new GridBagConstraints();
		gbc_textField_36.insets = new Insets(0, 0, 5, 0);
		gbc_textField_36.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_36.gridx = 3;
		gbc_textField_36.gridy = 0;
		pnlCop0Regs1.add(textField_36, gbc_textField_36);
		textField_36.setColumns(10);
		
		JLabel lblRandom = new JLabel("Random");
		GridBagConstraints gbc_lblRandom = new GridBagConstraints();
		gbc_lblRandom.anchor = GridBagConstraints.EAST;
		gbc_lblRandom.insets = new Insets(0, 0, 5, 5);
		gbc_lblRandom.gridx = 0;
		gbc_lblRandom.gridy = 1;
		pnlCop0Regs1.add(lblRandom, gbc_lblRandom);
		
		textField_37 = new JTextField();
		GridBagConstraints gbc_textField_37 = new GridBagConstraints();
		gbc_textField_37.insets = new Insets(0, 0, 5, 5);
		gbc_textField_37.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_37.gridx = 1;
		gbc_textField_37.gridy = 1;
		pnlCop0Regs1.add(textField_37, gbc_textField_37);
		textField_37.setColumns(10);
		
		JLabel lblLladdr = new JLabel("LLAddr");
		GridBagConstraints gbc_lblLladdr = new GridBagConstraints();
		gbc_lblLladdr.anchor = GridBagConstraints.EAST;
		gbc_lblLladdr.insets = new Insets(0, 0, 5, 5);
		gbc_lblLladdr.gridx = 2;
		gbc_lblLladdr.gridy = 1;
		pnlCop0Regs1.add(lblLladdr, gbc_lblLladdr);
		
		textField_52 = new JTextField();
		GridBagConstraints gbc_textField_52 = new GridBagConstraints();
		gbc_textField_52.insets = new Insets(0, 0, 5, 0);
		gbc_textField_52.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_52.gridx = 3;
		gbc_textField_52.gridy = 1;
		pnlCop0Regs1.add(textField_52, gbc_textField_52);
		textField_52.setColumns(10);
		
		JLabel lblEntrylo = new JLabel("EntryLo0");
		GridBagConstraints gbc_lblEntrylo = new GridBagConstraints();
		gbc_lblEntrylo.insets = new Insets(0, 0, 5, 5);
		gbc_lblEntrylo.gridx = 0;
		gbc_lblEntrylo.gridy = 2;
		pnlCop0Regs1.add(lblEntrylo, gbc_lblEntrylo);
		
		textField_38 = new JTextField();
		GridBagConstraints gbc_textField_38 = new GridBagConstraints();
		gbc_textField_38.insets = new Insets(0, 0, 5, 5);
		gbc_textField_38.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_38.gridx = 1;
		gbc_textField_38.gridy = 2;
		pnlCop0Regs1.add(textField_38, gbc_textField_38);
		textField_38.setColumns(10);
		
		JLabel lblWatchlo = new JLabel("WatchLO");
		GridBagConstraints gbc_lblWatchlo = new GridBagConstraints();
		gbc_lblWatchlo.anchor = GridBagConstraints.EAST;
		gbc_lblWatchlo.insets = new Insets(0, 0, 5, 5);
		gbc_lblWatchlo.gridx = 2;
		gbc_lblWatchlo.gridy = 2;
		pnlCop0Regs1.add(lblWatchlo, gbc_lblWatchlo);
		
		textField_53 = new JTextField();
		GridBagConstraints gbc_textField_53 = new GridBagConstraints();
		gbc_textField_53.insets = new Insets(0, 0, 5, 0);
		gbc_textField_53.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_53.gridx = 3;
		gbc_textField_53.gridy = 2;
		pnlCop0Regs1.add(textField_53, gbc_textField_53);
		textField_53.setColumns(10);
		
		JLabel lblBpc = new JLabel("BPC");
		GridBagConstraints gbc_lblBpc = new GridBagConstraints();
		gbc_lblBpc.anchor = GridBagConstraints.EAST;
		gbc_lblBpc.insets = new Insets(0, 0, 5, 5);
		gbc_lblBpc.gridx = 0;
		gbc_lblBpc.gridy = 3;
		pnlCop0Regs1.add(lblBpc, gbc_lblBpc);
		
		textField_39 = new JTextField();
		GridBagConstraints gbc_textField_39 = new GridBagConstraints();
		gbc_textField_39.insets = new Insets(0, 0, 5, 5);
		gbc_textField_39.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_39.gridx = 1;
		gbc_textField_39.gridy = 3;
		pnlCop0Regs1.add(textField_39, gbc_textField_39);
		textField_39.setColumns(10);
		
		JLabel lblWatchhi = new JLabel("WatchHI");
		GridBagConstraints gbc_lblWatchhi = new GridBagConstraints();
		gbc_lblWatchhi.anchor = GridBagConstraints.EAST;
		gbc_lblWatchhi.insets = new Insets(0, 0, 5, 5);
		gbc_lblWatchhi.gridx = 2;
		gbc_lblWatchhi.gridy = 3;
		pnlCop0Regs1.add(lblWatchhi, gbc_lblWatchhi);
		
		textField_54 = new JTextField();
		GridBagConstraints gbc_textField_54 = new GridBagConstraints();
		gbc_textField_54.insets = new Insets(0, 0, 5, 0);
		gbc_textField_54.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_54.gridx = 3;
		gbc_textField_54.gridy = 3;
		pnlCop0Regs1.add(textField_54, gbc_textField_54);
		textField_54.setColumns(10);
		
		JLabel lblContext = new JLabel("Context");
		GridBagConstraints gbc_lblContext = new GridBagConstraints();
		gbc_lblContext.anchor = GridBagConstraints.EAST;
		gbc_lblContext.insets = new Insets(0, 0, 5, 5);
		gbc_lblContext.gridx = 0;
		gbc_lblContext.gridy = 4;
		pnlCop0Regs1.add(lblContext, gbc_lblContext);
		
		textField_40 = new JTextField();
		GridBagConstraints gbc_textField_40 = new GridBagConstraints();
		gbc_textField_40.insets = new Insets(0, 0, 5, 5);
		gbc_textField_40.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_40.gridx = 1;
		gbc_textField_40.gridy = 4;
		pnlCop0Regs1.add(textField_40, gbc_textField_40);
		textField_40.setColumns(10);
		
		JLabel lblXcontext = new JLabel("XContext");
		GridBagConstraints gbc_lblXcontext = new GridBagConstraints();
		gbc_lblXcontext.anchor = GridBagConstraints.EAST;
		gbc_lblXcontext.insets = new Insets(0, 0, 5, 5);
		gbc_lblXcontext.gridx = 2;
		gbc_lblXcontext.gridy = 4;
		pnlCop0Regs1.add(lblXcontext, gbc_lblXcontext);
		
		textField_55 = new JTextField();
		GridBagConstraints gbc_textField_55 = new GridBagConstraints();
		gbc_textField_55.insets = new Insets(0, 0, 5, 0);
		gbc_textField_55.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_55.gridx = 3;
		gbc_textField_55.gridy = 4;
		pnlCop0Regs1.add(textField_55, gbc_textField_55);
		textField_55.setColumns(10);
		
		JLabel lblBda = new JLabel("BDA");
		GridBagConstraints gbc_lblBda = new GridBagConstraints();
		gbc_lblBda.anchor = GridBagConstraints.EAST;
		gbc_lblBda.insets = new Insets(0, 0, 5, 5);
		gbc_lblBda.gridx = 0;
		gbc_lblBda.gridy = 5;
		pnlCop0Regs1.add(lblBda, gbc_lblBda);
		
		textField_41 = new JTextField();
		GridBagConstraints gbc_textField_41 = new GridBagConstraints();
		gbc_textField_41.insets = new Insets(0, 0, 5, 5);
		gbc_textField_41.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_41.gridx = 1;
		gbc_textField_41.gridy = 5;
		pnlCop0Regs1.add(textField_41, gbc_textField_41);
		textField_41.setColumns(10);
		
		JLabel lblReserved = new JLabel("Reserved1");
		GridBagConstraints gbc_lblReserved = new GridBagConstraints();
		gbc_lblReserved.anchor = GridBagConstraints.EAST;
		gbc_lblReserved.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved.gridx = 2;
		gbc_lblReserved.gridy = 5;
		pnlCop0Regs1.add(lblReserved, gbc_lblReserved);
		
		textField_56 = new JTextField();
		GridBagConstraints gbc_textField_56 = new GridBagConstraints();
		gbc_textField_56.insets = new Insets(0, 0, 5, 0);
		gbc_textField_56.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_56.gridx = 3;
		gbc_textField_56.gridy = 5;
		pnlCop0Regs1.add(textField_56, gbc_textField_56);
		textField_56.setColumns(10);
		
		JLabel lblPidmask = new JLabel("PIDMask");
		GridBagConstraints gbc_lblPidmask = new GridBagConstraints();
		gbc_lblPidmask.anchor = GridBagConstraints.EAST;
		gbc_lblPidmask.insets = new Insets(0, 0, 5, 5);
		gbc_lblPidmask.gridx = 0;
		gbc_lblPidmask.gridy = 6;
		pnlCop0Regs1.add(lblPidmask, gbc_lblPidmask);
		
		textField_42 = new JTextField();
		GridBagConstraints gbc_textField_42 = new GridBagConstraints();
		gbc_textField_42.insets = new Insets(0, 0, 5, 5);
		gbc_textField_42.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_42.gridx = 1;
		gbc_textField_42.gridy = 6;
		pnlCop0Regs1.add(textField_42, gbc_textField_42);
		textField_42.setColumns(10);
		
		JLabel lblReserved_1 = new JLabel("Reserved2");
		GridBagConstraints gbc_lblReserved_1 = new GridBagConstraints();
		gbc_lblReserved_1.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved_1.gridx = 2;
		gbc_lblReserved_1.gridy = 6;
		pnlCop0Regs1.add(lblReserved_1, gbc_lblReserved_1);
		
		textField_57 = new JTextField();
		GridBagConstraints gbc_textField_57 = new GridBagConstraints();
		gbc_textField_57.insets = new Insets(0, 0, 5, 0);
		gbc_textField_57.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_57.gridx = 3;
		gbc_textField_57.gridy = 6;
		pnlCop0Regs1.add(textField_57, gbc_textField_57);
		textField_57.setColumns(10);
		
		JLabel lblDcic = new JLabel("DCIC");
		GridBagConstraints gbc_lblDcic = new GridBagConstraints();
		gbc_lblDcic.anchor = GridBagConstraints.EAST;
		gbc_lblDcic.insets = new Insets(0, 0, 5, 5);
		gbc_lblDcic.gridx = 0;
		gbc_lblDcic.gridy = 7;
		pnlCop0Regs1.add(lblDcic, gbc_lblDcic);
		
		textField_43 = new JTextField();
		GridBagConstraints gbc_textField_43 = new GridBagConstraints();
		gbc_textField_43.insets = new Insets(0, 0, 5, 5);
		gbc_textField_43.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_43.gridx = 1;
		gbc_textField_43.gridy = 7;
		pnlCop0Regs1.add(textField_43, gbc_textField_43);
		textField_43.setColumns(10);
		
		JLabel lblReserved_4 = new JLabel("Reserved3");
		GridBagConstraints gbc_lblReserved_4 = new GridBagConstraints();
		gbc_lblReserved_4.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_4.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved_4.gridx = 2;
		gbc_lblReserved_4.gridy = 7;
		pnlCop0Regs1.add(lblReserved_4, gbc_lblReserved_4);
		
		textField_58 = new JTextField();
		GridBagConstraints gbc_textField_58 = new GridBagConstraints();
		gbc_textField_58.insets = new Insets(0, 0, 5, 0);
		gbc_textField_58.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_58.gridx = 3;
		gbc_textField_58.gridy = 7;
		pnlCop0Regs1.add(textField_58, gbc_textField_58);
		textField_58.setColumns(10);
		
		JLabel lblBadvaddr = new JLabel("BadVAddr");
		GridBagConstraints gbc_lblBadvaddr = new GridBagConstraints();
		gbc_lblBadvaddr.anchor = GridBagConstraints.EAST;
		gbc_lblBadvaddr.insets = new Insets(0, 0, 5, 5);
		gbc_lblBadvaddr.gridx = 0;
		gbc_lblBadvaddr.gridy = 8;
		pnlCop0Regs1.add(lblBadvaddr, gbc_lblBadvaddr);
		
		textField_44 = new JTextField();
		GridBagConstraints gbc_textField_44 = new GridBagConstraints();
		gbc_textField_44.insets = new Insets(0, 0, 5, 5);
		gbc_textField_44.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_44.gridx = 1;
		gbc_textField_44.gridy = 8;
		pnlCop0Regs1.add(textField_44, gbc_textField_44);
		textField_44.setColumns(10);
		
		JLabel lblReserved_2 = new JLabel("Reserved4");
		GridBagConstraints gbc_lblReserved_2 = new GridBagConstraints();
		gbc_lblReserved_2.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved_2.gridx = 2;
		gbc_lblReserved_2.gridy = 8;
		pnlCop0Regs1.add(lblReserved_2, gbc_lblReserved_2);
		
		textField_59 = new JTextField();
		GridBagConstraints gbc_textField_59 = new GridBagConstraints();
		gbc_textField_59.insets = new Insets(0, 0, 5, 0);
		gbc_textField_59.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_59.gridx = 3;
		gbc_textField_59.gridy = 8;
		pnlCop0Regs1.add(textField_59, gbc_textField_59);
		textField_59.setColumns(10);
		
		JLabel lblBdam = new JLabel("BDAM");
		GridBagConstraints gbc_lblBdam = new GridBagConstraints();
		gbc_lblBdam.anchor = GridBagConstraints.EAST;
		gbc_lblBdam.insets = new Insets(0, 0, 5, 5);
		gbc_lblBdam.gridx = 0;
		gbc_lblBdam.gridy = 9;
		pnlCop0Regs1.add(lblBdam, gbc_lblBdam);
		
		textField_45 = new JTextField();
		GridBagConstraints gbc_textField_45 = new GridBagConstraints();
		gbc_textField_45.insets = new Insets(0, 0, 5, 5);
		gbc_textField_45.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_45.gridx = 1;
		gbc_textField_45.gridy = 9;
		pnlCop0Regs1.add(textField_45, gbc_textField_45);
		textField_45.setColumns(10);
		
		JLabel lblReserved_3 = new JLabel("Reserved5");
		GridBagConstraints gbc_lblReserved_3 = new GridBagConstraints();
		gbc_lblReserved_3.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_3.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved_3.gridx = 2;
		gbc_lblReserved_3.gridy = 9;
		pnlCop0Regs1.add(lblReserved_3, gbc_lblReserved_3);
		
		textField_60 = new JTextField();
		GridBagConstraints gbc_textField_60 = new GridBagConstraints();
		gbc_textField_60.insets = new Insets(0, 0, 5, 0);
		gbc_textField_60.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_60.gridx = 3;
		gbc_textField_60.gridy = 9;
		pnlCop0Regs1.add(textField_60, gbc_textField_60);
		textField_60.setColumns(10);
		
		JLabel lblEntryhi = new JLabel("EntryHi");
		GridBagConstraints gbc_lblEntryhi = new GridBagConstraints();
		gbc_lblEntryhi.anchor = GridBagConstraints.EAST;
		gbc_lblEntryhi.insets = new Insets(0, 0, 5, 5);
		gbc_lblEntryhi.gridx = 0;
		gbc_lblEntryhi.gridy = 10;
		pnlCop0Regs1.add(lblEntryhi, gbc_lblEntryhi);
		
		textField_46 = new JTextField();
		GridBagConstraints gbc_textField_46 = new GridBagConstraints();
		gbc_textField_46.insets = new Insets(0, 0, 5, 5);
		gbc_textField_46.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_46.gridx = 1;
		gbc_textField_46.gridy = 10;
		pnlCop0Regs1.add(textField_46, gbc_textField_46);
		textField_46.setColumns(10);
		
		JLabel lblEcc = new JLabel("ECC");
		GridBagConstraints gbc_lblEcc = new GridBagConstraints();
		gbc_lblEcc.anchor = GridBagConstraints.EAST;
		gbc_lblEcc.insets = new Insets(0, 0, 5, 5);
		gbc_lblEcc.gridx = 2;
		gbc_lblEcc.gridy = 10;
		pnlCop0Regs1.add(lblEcc, gbc_lblEcc);
		
		textField_61 = new JTextField();
		GridBagConstraints gbc_textField_61 = new GridBagConstraints();
		gbc_textField_61.insets = new Insets(0, 0, 5, 0);
		gbc_textField_61.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_61.gridx = 3;
		gbc_textField_61.gridy = 10;
		pnlCop0Regs1.add(textField_61, gbc_textField_61);
		textField_61.setColumns(10);
		
		JLabel lblBpcm = new JLabel("BPCM");
		GridBagConstraints gbc_lblBpcm = new GridBagConstraints();
		gbc_lblBpcm.anchor = GridBagConstraints.EAST;
		gbc_lblBpcm.insets = new Insets(0, 0, 5, 5);
		gbc_lblBpcm.gridx = 0;
		gbc_lblBpcm.gridy = 11;
		pnlCop0Regs1.add(lblBpcm, gbc_lblBpcm);
		
		textField_47 = new JTextField();
		GridBagConstraints gbc_textField_47 = new GridBagConstraints();
		gbc_textField_47.insets = new Insets(0, 0, 5, 5);
		gbc_textField_47.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_47.gridx = 1;
		gbc_textField_47.gridy = 11;
		pnlCop0Regs1.add(textField_47, gbc_textField_47);
		textField_47.setColumns(10);
		
		JLabel lblCacheerr = new JLabel("CacheErr");
		GridBagConstraints gbc_lblCacheerr = new GridBagConstraints();
		gbc_lblCacheerr.anchor = GridBagConstraints.EAST;
		gbc_lblCacheerr.insets = new Insets(0, 0, 5, 5);
		gbc_lblCacheerr.gridx = 2;
		gbc_lblCacheerr.gridy = 11;
		pnlCop0Regs1.add(lblCacheerr, gbc_lblCacheerr);
		
		textField_62 = new JTextField();
		GridBagConstraints gbc_textField_62 = new GridBagConstraints();
		gbc_textField_62.insets = new Insets(0, 0, 5, 0);
		gbc_textField_62.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_62.gridx = 3;
		gbc_textField_62.gridy = 11;
		pnlCop0Regs1.add(textField_62, gbc_textField_62);
		textField_62.setColumns(10);
		
		JLabel lblStatus = new JLabel("Status");
		GridBagConstraints gbc_lblStatus = new GridBagConstraints();
		gbc_lblStatus.anchor = GridBagConstraints.EAST;
		gbc_lblStatus.insets = new Insets(0, 0, 5, 5);
		gbc_lblStatus.gridx = 0;
		gbc_lblStatus.gridy = 12;
		pnlCop0Regs1.add(lblStatus, gbc_lblStatus);
		
		textField_48 = new JTextField();
		GridBagConstraints gbc_textField_48 = new GridBagConstraints();
		gbc_textField_48.insets = new Insets(0, 0, 5, 5);
		gbc_textField_48.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_48.gridx = 1;
		gbc_textField_48.gridy = 12;
		pnlCop0Regs1.add(textField_48, gbc_textField_48);
		textField_48.setColumns(10);
		
		JLabel lblTaglo = new JLabel("TagLo");
		GridBagConstraints gbc_lblTaglo = new GridBagConstraints();
		gbc_lblTaglo.anchor = GridBagConstraints.EAST;
		gbc_lblTaglo.insets = new Insets(0, 0, 5, 5);
		gbc_lblTaglo.gridx = 2;
		gbc_lblTaglo.gridy = 12;
		pnlCop0Regs1.add(lblTaglo, gbc_lblTaglo);
		
		textField_63 = new JTextField();
		GridBagConstraints gbc_textField_63 = new GridBagConstraints();
		gbc_textField_63.insets = new Insets(0, 0, 5, 0);
		gbc_textField_63.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_63.gridx = 3;
		gbc_textField_63.gridy = 12;
		pnlCop0Regs1.add(textField_63, gbc_textField_63);
		textField_63.setColumns(10);
		
		JLabel lblCause = new JLabel("Cause");
		GridBagConstraints gbc_lblCause = new GridBagConstraints();
		gbc_lblCause.anchor = GridBagConstraints.EAST;
		gbc_lblCause.insets = new Insets(0, 0, 5, 5);
		gbc_lblCause.gridx = 0;
		gbc_lblCause.gridy = 13;
		pnlCop0Regs1.add(lblCause, gbc_lblCause);
		
		textField_49 = new JTextField();
		GridBagConstraints gbc_textField_49 = new GridBagConstraints();
		gbc_textField_49.insets = new Insets(0, 0, 5, 5);
		gbc_textField_49.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_49.gridx = 1;
		gbc_textField_49.gridy = 13;
		pnlCop0Regs1.add(textField_49, gbc_textField_49);
		textField_49.setColumns(10);
		
		JLabel lblTaghi = new JLabel("TagHi");
		GridBagConstraints gbc_lblTaghi = new GridBagConstraints();
		gbc_lblTaghi.anchor = GridBagConstraints.EAST;
		gbc_lblTaghi.insets = new Insets(0, 0, 5, 5);
		gbc_lblTaghi.gridx = 2;
		gbc_lblTaghi.gridy = 13;
		pnlCop0Regs1.add(lblTaghi, gbc_lblTaghi);
		
		textField_64 = new JTextField();
		GridBagConstraints gbc_textField_64 = new GridBagConstraints();
		gbc_textField_64.insets = new Insets(0, 0, 5, 0);
		gbc_textField_64.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_64.gridx = 3;
		gbc_textField_64.gridy = 13;
		pnlCop0Regs1.add(textField_64, gbc_textField_64);
		textField_64.setColumns(10);
		
		JLabel lblEpc = new JLabel("EPC");
		GridBagConstraints gbc_lblEpc = new GridBagConstraints();
		gbc_lblEpc.anchor = GridBagConstraints.EAST;
		gbc_lblEpc.insets = new Insets(0, 0, 5, 5);
		gbc_lblEpc.gridx = 0;
		gbc_lblEpc.gridy = 14;
		pnlCop0Regs1.add(lblEpc, gbc_lblEpc);
		
		textField_50 = new JTextField();
		GridBagConstraints gbc_textField_50 = new GridBagConstraints();
		gbc_textField_50.insets = new Insets(0, 0, 5, 5);
		gbc_textField_50.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_50.gridx = 1;
		gbc_textField_50.gridy = 14;
		pnlCop0Regs1.add(textField_50, gbc_textField_50);
		textField_50.setColumns(10);
		
		JLabel lblErrorepc = new JLabel("ErrorEPC");
		GridBagConstraints gbc_lblErrorepc = new GridBagConstraints();
		gbc_lblErrorepc.anchor = GridBagConstraints.EAST;
		gbc_lblErrorepc.insets = new Insets(0, 0, 5, 5);
		gbc_lblErrorepc.gridx = 2;
		gbc_lblErrorepc.gridy = 14;
		pnlCop0Regs1.add(lblErrorepc, gbc_lblErrorepc);
		
		textField_65 = new JTextField();
		GridBagConstraints gbc_textField_65 = new GridBagConstraints();
		gbc_textField_65.insets = new Insets(0, 0, 5, 0);
		gbc_textField_65.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_65.gridx = 3;
		gbc_textField_65.gridy = 14;
		pnlCop0Regs1.add(textField_65, gbc_textField_65);
		textField_65.setColumns(10);
		
		JLabel lblPrid = new JLabel("PRid");
		GridBagConstraints gbc_lblPrid = new GridBagConstraints();
		gbc_lblPrid.anchor = GridBagConstraints.EAST;
		gbc_lblPrid.insets = new Insets(0, 0, 0, 5);
		gbc_lblPrid.gridx = 0;
		gbc_lblPrid.gridy = 15;
		pnlCop0Regs1.add(lblPrid, gbc_lblPrid);
		
		textField_51 = new JTextField();
		GridBagConstraints gbc_textField_51 = new GridBagConstraints();
		gbc_textField_51.insets = new Insets(0, 0, 0, 5);
		gbc_textField_51.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_51.gridx = 1;
		gbc_textField_51.gridy = 15;
		pnlCop0Regs1.add(textField_51, gbc_textField_51);
		textField_51.setColumns(10);
		
		JLabel lblReserved_5 = new JLabel("Reserved6");
		GridBagConstraints gbc_lblReserved_5 = new GridBagConstraints();
		gbc_lblReserved_5.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_5.insets = new Insets(0, 0, 0, 5);
		gbc_lblReserved_5.gridx = 2;
		gbc_lblReserved_5.gridy = 15;
		pnlCop0Regs1.add(lblReserved_5, gbc_lblReserved_5);
		
		textField_66 = new JTextField();
		GridBagConstraints gbc_textField_66 = new GridBagConstraints();
		gbc_textField_66.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_66.gridx = 3;
		gbc_textField_66.gridy = 15;
		pnlCop0Regs1.add(textField_66, gbc_textField_66);
		textField_66.setColumns(10);
		
		JPanel pnlCop2Data = new JPanel();
		tbbRegs.addTab("COP2 Data", null, pnlCop2Data, null);
		GridBagLayout gbl_pnlCop2Data = new GridBagLayout();
		gbl_pnlCop2Data.columnWidths = new int[]{217, 0};
		gbl_pnlCop2Data.rowHeights = new int[]{464, 0};
		gbl_pnlCop2Data.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_pnlCop2Data.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		pnlCop2Data.setLayout(gbl_pnlCop2Data);
		
		JPanel pnlCop2Data1 = new JPanel();
		GridBagConstraints gbc_pnlCop2Data1 = new GridBagConstraints();
		gbc_pnlCop2Data1.fill = GridBagConstraints.BOTH;
		gbc_pnlCop2Data1.gridx = 0;
		gbc_pnlCop2Data1.gridy = 0;
		pnlCop2Data.add(pnlCop2Data1, gbc_pnlCop2Data1);
		GridBagLayout gbl_pnlCop2Data1 = new GridBagLayout();
		gbl_pnlCop2Data1.columnWidths = new int[]{41, 0, 0, 0, 22, 0, 0, 0, 0, 0};
		gbl_pnlCop2Data1.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_pnlCop2Data1.columnWeights = new double[]{0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 1.0, 1.0, 1.0, Double.MIN_VALUE};
		gbl_pnlCop2Data1.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		pnlCop2Data1.setLayout(gbl_pnlCop2Data1);
		
		JLabel lblV = new JLabel("v0");
		GridBagConstraints gbc_lblV = new GridBagConstraints();
		gbc_lblV.insets = new Insets(0, 0, 5, 5);
		gbc_lblV.anchor = GridBagConstraints.EAST;
		gbc_lblV.gridx = 0;
		gbc_lblV.gridy = 0;
		pnlCop2Data1.add(lblV, gbc_lblV);
		
		textField_67 = new JTextField();
		GridBagConstraints gbc_textField_67 = new GridBagConstraints();
		gbc_textField_67.insets = new Insets(0, 0, 5, 5);
		gbc_textField_67.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_67.gridx = 1;
		gbc_textField_67.gridy = 0;
		pnlCop2Data1.add(textField_67, gbc_textField_67);
		textField_67.setColumns(10);
		
		textField_68 = new JTextField();
		GridBagConstraints gbc_textField_68 = new GridBagConstraints();
		gbc_textField_68.insets = new Insets(0, 0, 5, 5);
		gbc_textField_68.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_68.gridx = 2;
		gbc_textField_68.gridy = 0;
		pnlCop2Data1.add(textField_68, gbc_textField_68);
		textField_68.setColumns(10);
		
		textField_69 = new JTextField();
		GridBagConstraints gbc_textField_69 = new GridBagConstraints();
		gbc_textField_69.insets = new Insets(0, 0, 5, 5);
		gbc_textField_69.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_69.gridx = 3;
		gbc_textField_69.gridy = 0;
		pnlCop2Data1.add(textField_69, gbc_textField_69);
		textField_69.setColumns(10);
		
		JSeparator separator_8 = new JSeparator();
		separator_8.setOrientation(SwingConstants.VERTICAL);
		GridBagConstraints gbc_separator_8 = new GridBagConstraints();
		gbc_separator_8.fill = GridBagConstraints.VERTICAL;
		gbc_separator_8.gridheight = 17;
		gbc_separator_8.insets = new Insets(0, 0, 5, 5);
		gbc_separator_8.gridx = 4;
		gbc_separator_8.gridy = 0;
		pnlCop2Data1.add(separator_8, gbc_separator_8);
		
		JLabel lblRgb_1 = new JLabel("rgb0");
		GridBagConstraints gbc_lblRgb_1 = new GridBagConstraints();
		gbc_lblRgb_1.anchor = GridBagConstraints.EAST;
		gbc_lblRgb_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblRgb_1.gridx = 5;
		gbc_lblRgb_1.gridy = 0;
		pnlCop2Data1.add(lblRgb_1, gbc_lblRgb_1);
		
		textField_90 = new JTextField();
		GridBagConstraints gbc_textField_90 = new GridBagConstraints();
		gbc_textField_90.insets = new Insets(0, 0, 5, 5);
		gbc_textField_90.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_90.gridx = 6;
		gbc_textField_90.gridy = 0;
		pnlCop2Data1.add(textField_90, gbc_textField_90);
		textField_90.setColumns(10);
		
		textField_91 = new JTextField();
		GridBagConstraints gbc_textField_91 = new GridBagConstraints();
		gbc_textField_91.insets = new Insets(0, 0, 5, 5);
		gbc_textField_91.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_91.gridx = 7;
		gbc_textField_91.gridy = 0;
		pnlCop2Data1.add(textField_91, gbc_textField_91);
		textField_91.setColumns(10);
		
		textField_92 = new JTextField();
		GridBagConstraints gbc_textField_92 = new GridBagConstraints();
		gbc_textField_92.insets = new Insets(0, 0, 5, 0);
		gbc_textField_92.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_92.gridx = 8;
		gbc_textField_92.gridy = 0;
		pnlCop2Data1.add(textField_92, gbc_textField_92);
		textField_92.setColumns(10);
		
		JLabel lblV_1 = new JLabel("v1");
		GridBagConstraints gbc_lblV_1 = new GridBagConstraints();
		gbc_lblV_1.anchor = GridBagConstraints.EAST;
		gbc_lblV_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblV_1.gridx = 0;
		gbc_lblV_1.gridy = 1;
		pnlCop2Data1.add(lblV_1, gbc_lblV_1);
		
		textField_70 = new JTextField();
		GridBagConstraints gbc_textField_70 = new GridBagConstraints();
		gbc_textField_70.insets = new Insets(0, 0, 5, 5);
		gbc_textField_70.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_70.gridx = 1;
		gbc_textField_70.gridy = 1;
		pnlCop2Data1.add(textField_70, gbc_textField_70);
		textField_70.setColumns(10);
		
		textField_71 = new JTextField();
		GridBagConstraints gbc_textField_71 = new GridBagConstraints();
		gbc_textField_71.insets = new Insets(0, 0, 5, 5);
		gbc_textField_71.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_71.gridx = 2;
		gbc_textField_71.gridy = 1;
		pnlCop2Data1.add(textField_71, gbc_textField_71);
		textField_71.setColumns(10);
		
		textField_72 = new JTextField();
		GridBagConstraints gbc_textField_72 = new GridBagConstraints();
		gbc_textField_72.insets = new Insets(0, 0, 5, 5);
		gbc_textField_72.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_72.gridx = 3;
		gbc_textField_72.gridy = 1;
		pnlCop2Data1.add(textField_72, gbc_textField_72);
		textField_72.setColumns(10);
		
		JLabel lblRgb_2 = new JLabel("rgb1");
		GridBagConstraints gbc_lblRgb_2 = new GridBagConstraints();
		gbc_lblRgb_2.anchor = GridBagConstraints.EAST;
		gbc_lblRgb_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblRgb_2.gridx = 5;
		gbc_lblRgb_2.gridy = 1;
		pnlCop2Data1.add(lblRgb_2, gbc_lblRgb_2);
		
		textField_93 = new JTextField();
		GridBagConstraints gbc_textField_93 = new GridBagConstraints();
		gbc_textField_93.insets = new Insets(0, 0, 5, 5);
		gbc_textField_93.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_93.gridx = 6;
		gbc_textField_93.gridy = 1;
		pnlCop2Data1.add(textField_93, gbc_textField_93);
		textField_93.setColumns(10);
		
		textField_94 = new JTextField();
		GridBagConstraints gbc_textField_94 = new GridBagConstraints();
		gbc_textField_94.insets = new Insets(0, 0, 5, 5);
		gbc_textField_94.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_94.gridx = 7;
		gbc_textField_94.gridy = 1;
		pnlCop2Data1.add(textField_94, gbc_textField_94);
		textField_94.setColumns(10);
		
		textField_95 = new JTextField();
		GridBagConstraints gbc_textField_95 = new GridBagConstraints();
		gbc_textField_95.insets = new Insets(0, 0, 5, 0);
		gbc_textField_95.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_95.gridx = 8;
		gbc_textField_95.gridy = 1;
		pnlCop2Data1.add(textField_95, gbc_textField_95);
		textField_95.setColumns(10);
		
		JLabel lblV_2 = new JLabel("v2");
		GridBagConstraints gbc_lblV_2 = new GridBagConstraints();
		gbc_lblV_2.anchor = GridBagConstraints.EAST;
		gbc_lblV_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblV_2.gridx = 0;
		gbc_lblV_2.gridy = 2;
		pnlCop2Data1.add(lblV_2, gbc_lblV_2);
		
		textField_73 = new JTextField();
		GridBagConstraints gbc_textField_73 = new GridBagConstraints();
		gbc_textField_73.insets = new Insets(0, 0, 5, 5);
		gbc_textField_73.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_73.gridx = 1;
		gbc_textField_73.gridy = 2;
		pnlCop2Data1.add(textField_73, gbc_textField_73);
		textField_73.setColumns(10);
		
		textField_74 = new JTextField();
		GridBagConstraints gbc_textField_74 = new GridBagConstraints();
		gbc_textField_74.insets = new Insets(0, 0, 5, 5);
		gbc_textField_74.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_74.gridx = 2;
		gbc_textField_74.gridy = 2;
		pnlCop2Data1.add(textField_74, gbc_textField_74);
		textField_74.setColumns(10);
		
		textField_75 = new JTextField();
		GridBagConstraints gbc_textField_75 = new GridBagConstraints();
		gbc_textField_75.insets = new Insets(0, 0, 5, 5);
		gbc_textField_75.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_75.gridx = 3;
		gbc_textField_75.gridy = 2;
		pnlCop2Data1.add(textField_75, gbc_textField_75);
		textField_75.setColumns(10);
		
		JLabel lblRgb_3 = new JLabel("rgb2");
		GridBagConstraints gbc_lblRgb_3 = new GridBagConstraints();
		gbc_lblRgb_3.anchor = GridBagConstraints.EAST;
		gbc_lblRgb_3.insets = new Insets(0, 0, 5, 5);
		gbc_lblRgb_3.gridx = 5;
		gbc_lblRgb_3.gridy = 2;
		pnlCop2Data1.add(lblRgb_3, gbc_lblRgb_3);
		
		textField_96 = new JTextField();
		GridBagConstraints gbc_textField_96 = new GridBagConstraints();
		gbc_textField_96.insets = new Insets(0, 0, 5, 5);
		gbc_textField_96.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_96.gridx = 6;
		gbc_textField_96.gridy = 2;
		pnlCop2Data1.add(textField_96, gbc_textField_96);
		textField_96.setColumns(10);
		
		textField_97 = new JTextField();
		GridBagConstraints gbc_textField_97 = new GridBagConstraints();
		gbc_textField_97.insets = new Insets(0, 0, 5, 5);
		gbc_textField_97.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_97.gridx = 7;
		gbc_textField_97.gridy = 2;
		pnlCop2Data1.add(textField_97, gbc_textField_97);
		textField_97.setColumns(10);
		
		textField_98 = new JTextField();
		GridBagConstraints gbc_textField_98 = new GridBagConstraints();
		gbc_textField_98.insets = new Insets(0, 0, 5, 0);
		gbc_textField_98.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_98.gridx = 8;
		gbc_textField_98.gridy = 2;
		pnlCop2Data1.add(textField_98, gbc_textField_98);
		textField_98.setColumns(10);
		
		JLabel lblRgb = new JLabel("rgb");
		GridBagConstraints gbc_lblRgb = new GridBagConstraints();
		gbc_lblRgb.anchor = GridBagConstraints.EAST;
		gbc_lblRgb.insets = new Insets(0, 0, 5, 5);
		gbc_lblRgb.gridx = 0;
		gbc_lblRgb.gridy = 3;
		pnlCop2Data1.add(lblRgb, gbc_lblRgb);
		
		textField_76 = new JTextField();
		GridBagConstraints gbc_textField_76 = new GridBagConstraints();
		gbc_textField_76.gridwidth = 2;
		gbc_textField_76.insets = new Insets(0, 0, 5, 5);
		gbc_textField_76.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_76.gridx = 1;
		gbc_textField_76.gridy = 3;
		pnlCop2Data1.add(textField_76, gbc_textField_76);
		textField_76.setColumns(10);
		
		JLabel lblReserved_6 = new JLabel("reserved");
		GridBagConstraints gbc_lblReserved_6 = new GridBagConstraints();
		gbc_lblReserved_6.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_6.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved_6.gridx = 5;
		gbc_lblReserved_6.gridy = 3;
		pnlCop2Data1.add(lblReserved_6, gbc_lblReserved_6);
		
		textField_99 = new JTextField();
		GridBagConstraints gbc_textField_99 = new GridBagConstraints();
		gbc_textField_99.gridwidth = 2;
		gbc_textField_99.insets = new Insets(0, 0, 5, 5);
		gbc_textField_99.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_99.gridx = 6;
		gbc_textField_99.gridy = 3;
		pnlCop2Data1.add(textField_99, gbc_textField_99);
		textField_99.setColumns(10);
		
		JLabel lblOtz = new JLabel("otz");
		GridBagConstraints gbc_lblOtz = new GridBagConstraints();
		gbc_lblOtz.anchor = GridBagConstraints.EAST;
		gbc_lblOtz.insets = new Insets(0, 0, 5, 5);
		gbc_lblOtz.gridx = 0;
		gbc_lblOtz.gridy = 4;
		pnlCop2Data1.add(lblOtz, gbc_lblOtz);
		
		textField_77 = new JTextField();
		GridBagConstraints gbc_textField_77 = new GridBagConstraints();
		gbc_textField_77.gridwidth = 2;
		gbc_textField_77.insets = new Insets(0, 0, 5, 5);
		gbc_textField_77.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_77.gridx = 1;
		gbc_textField_77.gridy = 4;
		pnlCop2Data1.add(textField_77, gbc_textField_77);
		textField_77.setColumns(10);
		
		JLabel lblMac = new JLabel("mac0");
		GridBagConstraints gbc_lblMac = new GridBagConstraints();
		gbc_lblMac.anchor = GridBagConstraints.EAST;
		gbc_lblMac.insets = new Insets(0, 0, 5, 5);
		gbc_lblMac.gridx = 5;
		gbc_lblMac.gridy = 4;
		pnlCop2Data1.add(lblMac, gbc_lblMac);
		
		textField_100 = new JTextField();
		GridBagConstraints gbc_textField_100 = new GridBagConstraints();
		gbc_textField_100.gridwidth = 2;
		gbc_textField_100.insets = new Insets(0, 0, 5, 5);
		gbc_textField_100.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_100.gridx = 6;
		gbc_textField_100.gridy = 4;
		pnlCop2Data1.add(textField_100, gbc_textField_100);
		textField_100.setColumns(10);
		
		JLabel lblIr = new JLabel("ir0");
		GridBagConstraints gbc_lblIr = new GridBagConstraints();
		gbc_lblIr.anchor = GridBagConstraints.EAST;
		gbc_lblIr.insets = new Insets(0, 0, 5, 5);
		gbc_lblIr.gridx = 0;
		gbc_lblIr.gridy = 5;
		pnlCop2Data1.add(lblIr, gbc_lblIr);
		
		textField_78 = new JTextField();
		GridBagConstraints gbc_textField_78 = new GridBagConstraints();
		gbc_textField_78.gridwidth = 2;
		gbc_textField_78.insets = new Insets(0, 0, 5, 5);
		gbc_textField_78.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_78.gridx = 1;
		gbc_textField_78.gridy = 5;
		pnlCop2Data1.add(textField_78, gbc_textField_78);
		textField_78.setColumns(10);
		
		JLabel lblMac_1 = new JLabel("mac1");
		GridBagConstraints gbc_lblMac_1 = new GridBagConstraints();
		gbc_lblMac_1.anchor = GridBagConstraints.EAST;
		gbc_lblMac_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblMac_1.gridx = 5;
		gbc_lblMac_1.gridy = 5;
		pnlCop2Data1.add(lblMac_1, gbc_lblMac_1);
		
		textField_101 = new JTextField();
		GridBagConstraints gbc_textField_101 = new GridBagConstraints();
		gbc_textField_101.gridwidth = 2;
		gbc_textField_101.insets = new Insets(0, 0, 5, 5);
		gbc_textField_101.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_101.gridx = 6;
		gbc_textField_101.gridy = 5;
		pnlCop2Data1.add(textField_101, gbc_textField_101);
		textField_101.setColumns(10);
		
		JLabel lblIr_1 = new JLabel("ir1");
		GridBagConstraints gbc_lblIr_1 = new GridBagConstraints();
		gbc_lblIr_1.anchor = GridBagConstraints.EAST;
		gbc_lblIr_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblIr_1.gridx = 0;
		gbc_lblIr_1.gridy = 6;
		pnlCop2Data1.add(lblIr_1, gbc_lblIr_1);
		
		textField_79 = new JTextField();
		GridBagConstraints gbc_textField_79 = new GridBagConstraints();
		gbc_textField_79.gridwidth = 2;
		gbc_textField_79.insets = new Insets(0, 0, 5, 5);
		gbc_textField_79.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_79.gridx = 1;
		gbc_textField_79.gridy = 6;
		pnlCop2Data1.add(textField_79, gbc_textField_79);
		textField_79.setColumns(10);
		
		JLabel lblMac_2 = new JLabel("mac2");
		GridBagConstraints gbc_lblMac_2 = new GridBagConstraints();
		gbc_lblMac_2.anchor = GridBagConstraints.EAST;
		gbc_lblMac_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblMac_2.gridx = 5;
		gbc_lblMac_2.gridy = 6;
		pnlCop2Data1.add(lblMac_2, gbc_lblMac_2);
		
		textField_102 = new JTextField();
		GridBagConstraints gbc_textField_102 = new GridBagConstraints();
		gbc_textField_102.gridwidth = 2;
		gbc_textField_102.insets = new Insets(0, 0, 5, 5);
		gbc_textField_102.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_102.gridx = 6;
		gbc_textField_102.gridy = 6;
		pnlCop2Data1.add(textField_102, gbc_textField_102);
		textField_102.setColumns(10);
		
		JLabel lblIr_2 = new JLabel("ir2");
		GridBagConstraints gbc_lblIr_2 = new GridBagConstraints();
		gbc_lblIr_2.anchor = GridBagConstraints.EAST;
		gbc_lblIr_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblIr_2.gridx = 0;
		gbc_lblIr_2.gridy = 7;
		pnlCop2Data1.add(lblIr_2, gbc_lblIr_2);
		
		textField_80 = new JTextField();
		GridBagConstraints gbc_textField_80 = new GridBagConstraints();
		gbc_textField_80.gridwidth = 2;
		gbc_textField_80.insets = new Insets(0, 0, 5, 5);
		gbc_textField_80.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_80.gridx = 1;
		gbc_textField_80.gridy = 7;
		pnlCop2Data1.add(textField_80, gbc_textField_80);
		textField_80.setColumns(10);
		
		JLabel lblMac_3 = new JLabel("mac3");
		GridBagConstraints gbc_lblMac_3 = new GridBagConstraints();
		gbc_lblMac_3.anchor = GridBagConstraints.EAST;
		gbc_lblMac_3.insets = new Insets(0, 0, 5, 5);
		gbc_lblMac_3.gridx = 5;
		gbc_lblMac_3.gridy = 7;
		pnlCop2Data1.add(lblMac_3, gbc_lblMac_3);
		
		textField_103 = new JTextField();
		GridBagConstraints gbc_textField_103 = new GridBagConstraints();
		gbc_textField_103.gridwidth = 2;
		gbc_textField_103.insets = new Insets(0, 0, 5, 5);
		gbc_textField_103.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_103.gridx = 6;
		gbc_textField_103.gridy = 7;
		pnlCop2Data1.add(textField_103, gbc_textField_103);
		textField_103.setColumns(10);
		
		JLabel lblIr_3 = new JLabel("ir3");
		GridBagConstraints gbc_lblIr_3 = new GridBagConstraints();
		gbc_lblIr_3.anchor = GridBagConstraints.EAST;
		gbc_lblIr_3.insets = new Insets(0, 0, 5, 5);
		gbc_lblIr_3.gridx = 0;
		gbc_lblIr_3.gridy = 8;
		pnlCop2Data1.add(lblIr_3, gbc_lblIr_3);
		
		textField_81 = new JTextField();
		GridBagConstraints gbc_textField_81 = new GridBagConstraints();
		gbc_textField_81.gridwidth = 2;
		gbc_textField_81.insets = new Insets(0, 0, 5, 5);
		gbc_textField_81.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_81.gridx = 1;
		gbc_textField_81.gridy = 8;
		pnlCop2Data1.add(textField_81, gbc_textField_81);
		textField_81.setColumns(10);
		
		JLabel lblIrgb = new JLabel("irgb");
		GridBagConstraints gbc_lblIrgb = new GridBagConstraints();
		gbc_lblIrgb.anchor = GridBagConstraints.EAST;
		gbc_lblIrgb.insets = new Insets(0, 0, 5, 5);
		gbc_lblIrgb.gridx = 5;
		gbc_lblIrgb.gridy = 8;
		pnlCop2Data1.add(lblIrgb, gbc_lblIrgb);
		
		textField_104 = new JTextField();
		GridBagConstraints gbc_textField_104 = new GridBagConstraints();
		gbc_textField_104.gridwidth = 2;
		gbc_textField_104.insets = new Insets(0, 0, 5, 5);
		gbc_textField_104.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_104.gridx = 6;
		gbc_textField_104.gridy = 8;
		pnlCop2Data1.add(textField_104, gbc_textField_104);
		textField_104.setColumns(10);
		
		JLabel lblSxy = new JLabel("sxy0");
		GridBagConstraints gbc_lblSxy = new GridBagConstraints();
		gbc_lblSxy.anchor = GridBagConstraints.EAST;
		gbc_lblSxy.insets = new Insets(0, 0, 5, 5);
		gbc_lblSxy.gridx = 0;
		gbc_lblSxy.gridy = 9;
		pnlCop2Data1.add(lblSxy, gbc_lblSxy);
		
		textField_82 = new JTextField();
		GridBagConstraints gbc_textField_82 = new GridBagConstraints();
		gbc_textField_82.gridwidth = 2;
		gbc_textField_82.insets = new Insets(0, 0, 5, 5);
		gbc_textField_82.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_82.gridx = 1;
		gbc_textField_82.gridy = 9;
		pnlCop2Data1.add(textField_82, gbc_textField_82);
		textField_82.setColumns(10);
		
		JLabel lblOrgb = new JLabel("orgb");
		GridBagConstraints gbc_lblOrgb = new GridBagConstraints();
		gbc_lblOrgb.anchor = GridBagConstraints.EAST;
		gbc_lblOrgb.insets = new Insets(0, 0, 5, 5);
		gbc_lblOrgb.gridx = 5;
		gbc_lblOrgb.gridy = 9;
		pnlCop2Data1.add(lblOrgb, gbc_lblOrgb);
		
		textField_105 = new JTextField();
		GridBagConstraints gbc_textField_105 = new GridBagConstraints();
		gbc_textField_105.gridwidth = 2;
		gbc_textField_105.insets = new Insets(0, 0, 5, 5);
		gbc_textField_105.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_105.gridx = 6;
		gbc_textField_105.gridy = 9;
		pnlCop2Data1.add(textField_105, gbc_textField_105);
		textField_105.setColumns(10);
		
		JLabel lblSxy_1 = new JLabel("sxy1");
		GridBagConstraints gbc_lblSxy_1 = new GridBagConstraints();
		gbc_lblSxy_1.anchor = GridBagConstraints.EAST;
		gbc_lblSxy_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblSxy_1.gridx = 0;
		gbc_lblSxy_1.gridy = 10;
		pnlCop2Data1.add(lblSxy_1, gbc_lblSxy_1);
		
		textField_83 = new JTextField();
		GridBagConstraints gbc_textField_83 = new GridBagConstraints();
		gbc_textField_83.gridwidth = 2;
		gbc_textField_83.insets = new Insets(0, 0, 5, 5);
		gbc_textField_83.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_83.gridx = 1;
		gbc_textField_83.gridy = 10;
		pnlCop2Data1.add(textField_83, gbc_textField_83);
		textField_83.setColumns(10);
		
		JLabel lblLzcs = new JLabel("lzcs");
		GridBagConstraints gbc_lblLzcs = new GridBagConstraints();
		gbc_lblLzcs.anchor = GridBagConstraints.EAST;
		gbc_lblLzcs.insets = new Insets(0, 0, 5, 5);
		gbc_lblLzcs.gridx = 5;
		gbc_lblLzcs.gridy = 10;
		pnlCop2Data1.add(lblLzcs, gbc_lblLzcs);
		
		textField_106 = new JTextField();
		GridBagConstraints gbc_textField_106 = new GridBagConstraints();
		gbc_textField_106.gridwidth = 2;
		gbc_textField_106.insets = new Insets(0, 0, 5, 5);
		gbc_textField_106.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_106.gridx = 6;
		gbc_textField_106.gridy = 10;
		pnlCop2Data1.add(textField_106, gbc_textField_106);
		textField_106.setColumns(10);
		
		JLabel lblSxy_2 = new JLabel("sxy2");
		GridBagConstraints gbc_lblSxy_2 = new GridBagConstraints();
		gbc_lblSxy_2.anchor = GridBagConstraints.EAST;
		gbc_lblSxy_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblSxy_2.gridx = 0;
		gbc_lblSxy_2.gridy = 11;
		pnlCop2Data1.add(lblSxy_2, gbc_lblSxy_2);
		
		textField_84 = new JTextField();
		GridBagConstraints gbc_textField_84 = new GridBagConstraints();
		gbc_textField_84.gridwidth = 2;
		gbc_textField_84.insets = new Insets(0, 0, 5, 5);
		gbc_textField_84.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_84.gridx = 1;
		gbc_textField_84.gridy = 11;
		pnlCop2Data1.add(textField_84, gbc_textField_84);
		textField_84.setColumns(10);
		
		JLabel lblLzcr = new JLabel("lzcr");
		GridBagConstraints gbc_lblLzcr = new GridBagConstraints();
		gbc_lblLzcr.anchor = GridBagConstraints.EAST;
		gbc_lblLzcr.insets = new Insets(0, 0, 5, 5);
		gbc_lblLzcr.gridx = 5;
		gbc_lblLzcr.gridy = 11;
		pnlCop2Data1.add(lblLzcr, gbc_lblLzcr);
		
		textField_107 = new JTextField();
		GridBagConstraints gbc_textField_107 = new GridBagConstraints();
		gbc_textField_107.gridwidth = 2;
		gbc_textField_107.insets = new Insets(0, 0, 5, 5);
		gbc_textField_107.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_107.gridx = 6;
		gbc_textField_107.gridy = 11;
		pnlCop2Data1.add(textField_107, gbc_textField_107);
		textField_107.setColumns(10);
		
		JLabel lblSxyp = new JLabel("sxyp");
		GridBagConstraints gbc_lblSxyp = new GridBagConstraints();
		gbc_lblSxyp.anchor = GridBagConstraints.EAST;
		gbc_lblSxyp.insets = new Insets(0, 0, 5, 5);
		gbc_lblSxyp.gridx = 0;
		gbc_lblSxyp.gridy = 12;
		pnlCop2Data1.add(lblSxyp, gbc_lblSxyp);
		
		textField_85 = new JTextField();
		GridBagConstraints gbc_textField_85 = new GridBagConstraints();
		gbc_textField_85.gridwidth = 2;
		gbc_textField_85.insets = new Insets(0, 0, 5, 5);
		gbc_textField_85.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_85.gridx = 1;
		gbc_textField_85.gridy = 12;
		pnlCop2Data1.add(textField_85, gbc_textField_85);
		textField_85.setColumns(10);
		
		JLabel lblSz = new JLabel("sz0");
		GridBagConstraints gbc_lblSz = new GridBagConstraints();
		gbc_lblSz.anchor = GridBagConstraints.EAST;
		gbc_lblSz.insets = new Insets(0, 0, 5, 5);
		gbc_lblSz.gridx = 0;
		gbc_lblSz.gridy = 13;
		pnlCop2Data1.add(lblSz, gbc_lblSz);
		
		textField_86 = new JTextField();
		GridBagConstraints gbc_textField_86 = new GridBagConstraints();
		gbc_textField_86.gridwidth = 2;
		gbc_textField_86.insets = new Insets(0, 0, 5, 5);
		gbc_textField_86.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_86.gridx = 1;
		gbc_textField_86.gridy = 13;
		pnlCop2Data1.add(textField_86, gbc_textField_86);
		textField_86.setColumns(10);
		
		JLabel lblSz_1 = new JLabel("sz1");
		GridBagConstraints gbc_lblSz_1 = new GridBagConstraints();
		gbc_lblSz_1.anchor = GridBagConstraints.EAST;
		gbc_lblSz_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblSz_1.gridx = 0;
		gbc_lblSz_1.gridy = 14;
		pnlCop2Data1.add(lblSz_1, gbc_lblSz_1);
		
		textField_87 = new JTextField();
		GridBagConstraints gbc_textField_87 = new GridBagConstraints();
		gbc_textField_87.gridwidth = 2;
		gbc_textField_87.insets = new Insets(0, 0, 5, 5);
		gbc_textField_87.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_87.gridx = 1;
		gbc_textField_87.gridy = 14;
		pnlCop2Data1.add(textField_87, gbc_textField_87);
		textField_87.setColumns(10);
		
		JLabel lblSz_2 = new JLabel("sz2");
		GridBagConstraints gbc_lblSz_2 = new GridBagConstraints();
		gbc_lblSz_2.anchor = GridBagConstraints.EAST;
		gbc_lblSz_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblSz_2.gridx = 0;
		gbc_lblSz_2.gridy = 15;
		pnlCop2Data1.add(lblSz_2, gbc_lblSz_2);
		
		textField_88 = new JTextField();
		GridBagConstraints gbc_textField_88 = new GridBagConstraints();
		gbc_textField_88.gridwidth = 2;
		gbc_textField_88.insets = new Insets(0, 0, 5, 5);
		gbc_textField_88.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_88.gridx = 1;
		gbc_textField_88.gridy = 15;
		pnlCop2Data1.add(textField_88, gbc_textField_88);
		textField_88.setColumns(10);
		
		JLabel lblSz_3 = new JLabel("sz3");
		GridBagConstraints gbc_lblSz_3 = new GridBagConstraints();
		gbc_lblSz_3.anchor = GridBagConstraints.EAST;
		gbc_lblSz_3.insets = new Insets(0, 0, 0, 5);
		gbc_lblSz_3.gridx = 0;
		gbc_lblSz_3.gridy = 16;
		pnlCop2Data1.add(lblSz_3, gbc_lblSz_3);
		
		textField_89 = new JTextField();
		GridBagConstraints gbc_textField_89 = new GridBagConstraints();
		gbc_textField_89.gridwidth = 2;
		gbc_textField_89.insets = new Insets(0, 0, 0, 5);
		gbc_textField_89.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_89.gridx = 1;
		gbc_textField_89.gridy = 16;
		pnlCop2Data1.add(textField_89, gbc_textField_89);
		textField_89.setColumns(10);
		
		JPanel pnlCop2Ctrl = new JPanel();
		tbbRegs.addTab("COP2 Control", null, pnlCop2Ctrl, null);
		GridBagLayout gbl_pnlCop2Ctrl = new GridBagLayout();
		gbl_pnlCop2Ctrl.columnWidths = new int[]{107, 0};
		gbl_pnlCop2Ctrl.rowHeights = new int[]{320, 0};
		gbl_pnlCop2Ctrl.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_pnlCop2Ctrl.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		pnlCop2Ctrl.setLayout(gbl_pnlCop2Ctrl);
		
		JPanel pnlCop2Ctrl1 = new JPanel();
		GridBagConstraints gbc_pnlCop2Ctrl1 = new GridBagConstraints();
		gbc_pnlCop2Ctrl1.fill = GridBagConstraints.VERTICAL;
		gbc_pnlCop2Ctrl1.anchor = GridBagConstraints.WEST;
		gbc_pnlCop2Ctrl1.gridx = 0;
		gbc_pnlCop2Ctrl1.gridy = 0;
		pnlCop2Ctrl.add(pnlCop2Ctrl1, gbc_pnlCop2Ctrl1);
		GridBagLayout gbl_pnlCop2Ctrl1 = new GridBagLayout();
		gbl_pnlCop2Ctrl1.columnWidths = new int[]{57, 0, 0, 0, 0};
		gbl_pnlCop2Ctrl1.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_pnlCop2Ctrl1.columnWeights = new double[]{0.0, 1.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_pnlCop2Ctrl1.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		pnlCop2Ctrl1.setLayout(gbl_pnlCop2Ctrl1);
		
		JLabel lblRmatrix = new JLabel("rMatrix");
		GridBagConstraints gbc_lblRmatrix = new GridBagConstraints();
		gbc_lblRmatrix.anchor = GridBagConstraints.EAST;
		gbc_lblRmatrix.insets = new Insets(0, 0, 5, 5);
		gbc_lblRmatrix.gridx = 0;
		gbc_lblRmatrix.gridy = 0;
		pnlCop2Ctrl1.add(lblRmatrix, gbc_lblRmatrix);
		
		textField_108 = new JTextField();
		GridBagConstraints gbc_textField_108 = new GridBagConstraints();
		gbc_textField_108.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_108.insets = new Insets(0, 0, 5, 5);
		gbc_textField_108.gridx = 1;
		gbc_textField_108.gridy = 0;
		pnlCop2Ctrl1.add(textField_108, gbc_textField_108);
		textField_108.setColumns(10);
		
		JLabel lblOfx = new JLabel("ofx");
		GridBagConstraints gbc_lblOfx = new GridBagConstraints();
		gbc_lblOfx.anchor = GridBagConstraints.EAST;
		gbc_lblOfx.insets = new Insets(0, 0, 5, 5);
		gbc_lblOfx.gridx = 2;
		gbc_lblOfx.gridy = 0;
		pnlCop2Ctrl1.add(lblOfx, gbc_lblOfx);
		
		textField_118 = new JTextField();
		GridBagConstraints gbc_textField_118 = new GridBagConstraints();
		gbc_textField_118.insets = new Insets(0, 0, 5, 0);
		gbc_textField_118.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_118.gridx = 3;
		gbc_textField_118.gridy = 0;
		pnlCop2Ctrl1.add(textField_118, gbc_textField_118);
		textField_118.setColumns(10);
		
		JLabel lblTrx = new JLabel("trX");
		GridBagConstraints gbc_lblTrx = new GridBagConstraints();
		gbc_lblTrx.anchor = GridBagConstraints.EAST;
		gbc_lblTrx.insets = new Insets(0, 0, 5, 5);
		gbc_lblTrx.gridx = 0;
		gbc_lblTrx.gridy = 1;
		pnlCop2Ctrl1.add(lblTrx, gbc_lblTrx);
		
		textField_109 = new JTextField();
		GridBagConstraints gbc_textField_109 = new GridBagConstraints();
		gbc_textField_109.insets = new Insets(0, 0, 5, 5);
		gbc_textField_109.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_109.gridx = 1;
		gbc_textField_109.gridy = 1;
		pnlCop2Ctrl1.add(textField_109, gbc_textField_109);
		textField_109.setColumns(10);
		
		JLabel lblOfy = new JLabel("ofy");
		GridBagConstraints gbc_lblOfy = new GridBagConstraints();
		gbc_lblOfy.anchor = GridBagConstraints.EAST;
		gbc_lblOfy.insets = new Insets(0, 0, 5, 5);
		gbc_lblOfy.gridx = 2;
		gbc_lblOfy.gridy = 1;
		pnlCop2Ctrl1.add(lblOfy, gbc_lblOfy);
		
		textField_121 = new JTextField();
		GridBagConstraints gbc_textField_121 = new GridBagConstraints();
		gbc_textField_121.insets = new Insets(0, 0, 5, 0);
		gbc_textField_121.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_121.gridx = 3;
		gbc_textField_121.gridy = 1;
		pnlCop2Ctrl1.add(textField_121, gbc_textField_121);
		textField_121.setColumns(10);
		
		JLabel lblTry = new JLabel("trY");
		GridBagConstraints gbc_lblTry = new GridBagConstraints();
		gbc_lblTry.anchor = GridBagConstraints.EAST;
		gbc_lblTry.insets = new Insets(0, 0, 5, 5);
		gbc_lblTry.gridx = 0;
		gbc_lblTry.gridy = 2;
		pnlCop2Ctrl1.add(lblTry, gbc_lblTry);
		
		textField_110 = new JTextField();
		GridBagConstraints gbc_textField_110 = new GridBagConstraints();
		gbc_textField_110.insets = new Insets(0, 0, 5, 5);
		gbc_textField_110.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_110.gridx = 1;
		gbc_textField_110.gridy = 2;
		pnlCop2Ctrl1.add(textField_110, gbc_textField_110);
		textField_110.setColumns(10);
		
		JLabel lblH = new JLabel("h");
		GridBagConstraints gbc_lblH = new GridBagConstraints();
		gbc_lblH.insets = new Insets(0, 0, 5, 5);
		gbc_lblH.gridx = 2;
		gbc_lblH.gridy = 2;
		pnlCop2Ctrl1.add(lblH, gbc_lblH);
		
		textField_122 = new JTextField();
		GridBagConstraints gbc_textField_122 = new GridBagConstraints();
		gbc_textField_122.insets = new Insets(0, 0, 5, 0);
		gbc_textField_122.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_122.gridx = 3;
		gbc_textField_122.gridy = 2;
		pnlCop2Ctrl1.add(textField_122, gbc_textField_122);
		textField_122.setColumns(10);
		
		JLabel lblTrz = new JLabel("trZ");
		GridBagConstraints gbc_lblTrz = new GridBagConstraints();
		gbc_lblTrz.anchor = GridBagConstraints.EAST;
		gbc_lblTrz.insets = new Insets(0, 0, 5, 5);
		gbc_lblTrz.gridx = 0;
		gbc_lblTrz.gridy = 3;
		pnlCop2Ctrl1.add(lblTrz, gbc_lblTrz);
		
		textField_111 = new JTextField();
		GridBagConstraints gbc_textField_111 = new GridBagConstraints();
		gbc_textField_111.insets = new Insets(0, 0, 5, 5);
		gbc_textField_111.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_111.gridx = 1;
		gbc_textField_111.gridy = 3;
		pnlCop2Ctrl1.add(textField_111, gbc_textField_111);
		textField_111.setColumns(10);
		
		JLabel lblDqa = new JLabel("dqa");
		GridBagConstraints gbc_lblDqa = new GridBagConstraints();
		gbc_lblDqa.anchor = GridBagConstraints.EAST;
		gbc_lblDqa.insets = new Insets(0, 0, 5, 5);
		gbc_lblDqa.gridx = 2;
		gbc_lblDqa.gridy = 3;
		pnlCop2Ctrl1.add(lblDqa, gbc_lblDqa);
		
		textField_123 = new JTextField();
		GridBagConstraints gbc_textField_123 = new GridBagConstraints();
		gbc_textField_123.insets = new Insets(0, 0, 5, 0);
		gbc_textField_123.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_123.gridx = 3;
		gbc_textField_123.gridy = 3;
		pnlCop2Ctrl1.add(textField_123, gbc_textField_123);
		textField_123.setColumns(10);
		
		JLabel lblLmatrix = new JLabel("lMatrix");
		GridBagConstraints gbc_lblLmatrix = new GridBagConstraints();
		gbc_lblLmatrix.anchor = GridBagConstraints.EAST;
		gbc_lblLmatrix.insets = new Insets(0, 0, 5, 5);
		gbc_lblLmatrix.gridx = 0;
		gbc_lblLmatrix.gridy = 4;
		pnlCop2Ctrl1.add(lblLmatrix, gbc_lblLmatrix);
		
		textField_112 = new JTextField();
		GridBagConstraints gbc_textField_112 = new GridBagConstraints();
		gbc_textField_112.insets = new Insets(0, 0, 5, 5);
		gbc_textField_112.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_112.gridx = 1;
		gbc_textField_112.gridy = 4;
		pnlCop2Ctrl1.add(textField_112, gbc_textField_112);
		textField_112.setColumns(10);
		
		JLabel lblDqb = new JLabel("dqb");
		GridBagConstraints gbc_lblDqb = new GridBagConstraints();
		gbc_lblDqb.anchor = GridBagConstraints.EAST;
		gbc_lblDqb.insets = new Insets(0, 0, 5, 5);
		gbc_lblDqb.gridx = 2;
		gbc_lblDqb.gridy = 4;
		pnlCop2Ctrl1.add(lblDqb, gbc_lblDqb);
		
		textField_124 = new JTextField();
		GridBagConstraints gbc_textField_124 = new GridBagConstraints();
		gbc_textField_124.insets = new Insets(0, 0, 5, 0);
		gbc_textField_124.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_124.gridx = 3;
		gbc_textField_124.gridy = 4;
		pnlCop2Ctrl1.add(textField_124, gbc_textField_124);
		textField_124.setColumns(10);
		
		JLabel lblRbk = new JLabel("rbk");
		GridBagConstraints gbc_lblRbk = new GridBagConstraints();
		gbc_lblRbk.anchor = GridBagConstraints.EAST;
		gbc_lblRbk.insets = new Insets(0, 0, 5, 5);
		gbc_lblRbk.gridx = 0;
		gbc_lblRbk.gridy = 5;
		pnlCop2Ctrl1.add(lblRbk, gbc_lblRbk);
		
		textField_113 = new JTextField();
		GridBagConstraints gbc_textField_113 = new GridBagConstraints();
		gbc_textField_113.insets = new Insets(0, 0, 5, 5);
		gbc_textField_113.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_113.gridx = 1;
		gbc_textField_113.gridy = 5;
		pnlCop2Ctrl1.add(textField_113, gbc_textField_113);
		textField_113.setColumns(10);
		
		JLabel lblZsf = new JLabel("zsf3");
		GridBagConstraints gbc_lblZsf = new GridBagConstraints();
		gbc_lblZsf.anchor = GridBagConstraints.EAST;
		gbc_lblZsf.insets = new Insets(0, 0, 5, 5);
		gbc_lblZsf.gridx = 2;
		gbc_lblZsf.gridy = 5;
		pnlCop2Ctrl1.add(lblZsf, gbc_lblZsf);
		
		textField_125 = new JTextField();
		GridBagConstraints gbc_textField_125 = new GridBagConstraints();
		gbc_textField_125.insets = new Insets(0, 0, 5, 0);
		gbc_textField_125.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_125.gridx = 3;
		gbc_textField_125.gridy = 5;
		pnlCop2Ctrl1.add(textField_125, gbc_textField_125);
		textField_125.setColumns(10);
		
		JLabel lblGbk = new JLabel("gbk");
		GridBagConstraints gbc_lblGbk = new GridBagConstraints();
		gbc_lblGbk.anchor = GridBagConstraints.EAST;
		gbc_lblGbk.insets = new Insets(0, 0, 5, 5);
		gbc_lblGbk.gridx = 0;
		gbc_lblGbk.gridy = 6;
		pnlCop2Ctrl1.add(lblGbk, gbc_lblGbk);
		
		textField_114 = new JTextField();
		GridBagConstraints gbc_textField_114 = new GridBagConstraints();
		gbc_textField_114.insets = new Insets(0, 0, 5, 5);
		gbc_textField_114.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_114.gridx = 1;
		gbc_textField_114.gridy = 6;
		pnlCop2Ctrl1.add(textField_114, gbc_textField_114);
		textField_114.setColumns(10);
		
		JLabel lblZsf_1 = new JLabel("zsf4");
		GridBagConstraints gbc_lblZsf_1 = new GridBagConstraints();
		gbc_lblZsf_1.anchor = GridBagConstraints.EAST;
		gbc_lblZsf_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblZsf_1.gridx = 2;
		gbc_lblZsf_1.gridy = 6;
		pnlCop2Ctrl1.add(lblZsf_1, gbc_lblZsf_1);
		
		textField_126 = new JTextField();
		GridBagConstraints gbc_textField_126 = new GridBagConstraints();
		gbc_textField_126.insets = new Insets(0, 0, 5, 0);
		gbc_textField_126.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_126.gridx = 3;
		gbc_textField_126.gridy = 6;
		pnlCop2Ctrl1.add(textField_126, gbc_textField_126);
		textField_126.setColumns(10);
		
		JLabel lblBbk = new JLabel("bbk");
		GridBagConstraints gbc_lblBbk = new GridBagConstraints();
		gbc_lblBbk.anchor = GridBagConstraints.EAST;
		gbc_lblBbk.insets = new Insets(0, 0, 5, 5);
		gbc_lblBbk.gridx = 0;
		gbc_lblBbk.gridy = 7;
		pnlCop2Ctrl1.add(lblBbk, gbc_lblBbk);
		
		textField_115 = new JTextField();
		GridBagConstraints gbc_textField_115 = new GridBagConstraints();
		gbc_textField_115.insets = new Insets(0, 0, 5, 5);
		gbc_textField_115.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_115.gridx = 1;
		gbc_textField_115.gridy = 7;
		pnlCop2Ctrl1.add(textField_115, gbc_textField_115);
		textField_115.setColumns(10);
		
		JLabel lblFlag = new JLabel("flag");
		GridBagConstraints gbc_lblFlag = new GridBagConstraints();
		gbc_lblFlag.anchor = GridBagConstraints.EAST;
		gbc_lblFlag.insets = new Insets(0, 0, 5, 5);
		gbc_lblFlag.gridx = 2;
		gbc_lblFlag.gridy = 7;
		pnlCop2Ctrl1.add(lblFlag, gbc_lblFlag);
		
		textField_127 = new JTextField();
		GridBagConstraints gbc_textField_127 = new GridBagConstraints();
		gbc_textField_127.insets = new Insets(0, 0, 5, 0);
		gbc_textField_127.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_127.gridx = 3;
		gbc_textField_127.gridy = 7;
		pnlCop2Ctrl1.add(textField_127, gbc_textField_127);
		textField_127.setColumns(10);
		
		JLabel lblCmatrix = new JLabel("cMatrix");
		GridBagConstraints gbc_lblCmatrix = new GridBagConstraints();
		gbc_lblCmatrix.anchor = GridBagConstraints.EAST;
		gbc_lblCmatrix.insets = new Insets(0, 0, 5, 5);
		gbc_lblCmatrix.gridx = 0;
		gbc_lblCmatrix.gridy = 8;
		pnlCop2Ctrl1.add(lblCmatrix, gbc_lblCmatrix);
		
		textField_116 = new JTextField();
		GridBagConstraints gbc_textField_116 = new GridBagConstraints();
		gbc_textField_116.insets = new Insets(0, 0, 5, 5);
		gbc_textField_116.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_116.gridx = 1;
		gbc_textField_116.gridy = 8;
		pnlCop2Ctrl1.add(textField_116, gbc_textField_116);
		textField_116.setColumns(10);
		
		JLabel lblRfc = new JLabel("rfc");
		GridBagConstraints gbc_lblRfc = new GridBagConstraints();
		gbc_lblRfc.anchor = GridBagConstraints.EAST;
		gbc_lblRfc.insets = new Insets(0, 0, 5, 5);
		gbc_lblRfc.gridx = 0;
		gbc_lblRfc.gridy = 9;
		pnlCop2Ctrl1.add(lblRfc, gbc_lblRfc);
		
		textField_117 = new JTextField();
		GridBagConstraints gbc_textField_117 = new GridBagConstraints();
		gbc_textField_117.insets = new Insets(0, 0, 5, 5);
		gbc_textField_117.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_117.gridx = 1;
		gbc_textField_117.gridy = 9;
		pnlCop2Ctrl1.add(textField_117, gbc_textField_117);
		textField_117.setColumns(10);
		
		JLabel lblGfc = new JLabel("gfc");
		GridBagConstraints gbc_lblGfc = new GridBagConstraints();
		gbc_lblGfc.anchor = GridBagConstraints.EAST;
		gbc_lblGfc.insets = new Insets(0, 0, 5, 5);
		gbc_lblGfc.gridx = 0;
		gbc_lblGfc.gridy = 10;
		pnlCop2Ctrl1.add(lblGfc, gbc_lblGfc);
		
		textField_119 = new JTextField();
		GridBagConstraints gbc_textField_119 = new GridBagConstraints();
		gbc_textField_119.insets = new Insets(0, 0, 5, 5);
		gbc_textField_119.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_119.gridx = 1;
		gbc_textField_119.gridy = 10;
		pnlCop2Ctrl1.add(textField_119, gbc_textField_119);
		textField_119.setColumns(10);
		
		JLabel lblBfc = new JLabel("bfc");
		GridBagConstraints gbc_lblBfc = new GridBagConstraints();
		gbc_lblBfc.anchor = GridBagConstraints.EAST;
		gbc_lblBfc.insets = new Insets(0, 0, 0, 5);
		gbc_lblBfc.gridx = 0;
		gbc_lblBfc.gridy = 11;
		pnlCop2Ctrl1.add(lblBfc, gbc_lblBfc);
		
		textField_120 = new JTextField();
		GridBagConstraints gbc_textField_120 = new GridBagConstraints();
		gbc_textField_120.insets = new Insets(0, 0, 0, 5);
		gbc_textField_120.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_120.gridx = 1;
		gbc_textField_120.gridy = 11;
		pnlCop2Ctrl1.add(textField_120, gbc_textField_120);
		textField_120.setColumns(10);
		
		tbbRegs.setSelectedIndex(0);

	}

}
