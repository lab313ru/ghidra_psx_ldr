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
	private JTextField textField;
	private JTextField textField_1;
	private JTextField textField_2;
	private JTextField textField_3;
	private JTextField textField_4;
	private JTextField textField_5;
	private JTextField textField_6;
	private JTextField textField_7;
	private JTextField textField_8;
	private JTextField textField_9;
	private JTextField textField_10;
	private JTextField textField_11;
	private JTextField textField_12;
	private JTextField textField_13;
	private JTextField textField_14;
	private JTextField textField_15;
	private JTextField textField_16;
	private JTextField textField_17;
	private JTextField textField_18;
	private JTextField textField_19;
	private JTextField textField_20;
	private JTextField textField_21;
	private JTextField textField_22;
	private JTextField textField_23;
	private JTextField textField_24;
	private JTextField textField_25;
	private JTextField textField_26;
	private JTextField textField_27;
	private JTextField textField_28;
	private JTextField textField_29;
	private JTextField textField_30;
	private JTextField textField_31;
	private JTextField textField_32;
	private JTextField textField_33;
	private JTextField textField_34;
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
		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 1, true), "CPU Control", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagConstraints gbc_panel = new GridBagConstraints();
		gbc_panel.fill = GridBagConstraints.HORIZONTAL;
		gbc_panel.anchor = GridBagConstraints.NORTH;
		gbc_panel.insets = new Insets(0, 0, 0, 5);
		gbc_panel.gridx = 0;
		gbc_panel.gridy = 0;
		add(panel, gbc_panel);
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{107, 0};
		gbl_panel.rowHeights = new int[]{0, 0, 0, 0, 0};
		gbl_panel.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel.setLayout(gbl_panel);
		
		JButton btnStepInto = new JButton("Step Into");
		GridBagConstraints gbc_btnStepInto = new GridBagConstraints();
		gbc_btnStepInto.insets = new Insets(0, 0, 5, 0);
		gbc_btnStepInto.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnStepInto.gridx = 0;
		gbc_btnStepInto.gridy = 0;
		panel.add(btnStepInto, gbc_btnStepInto);
		
		JButton btnStepOver = new JButton("Step Over");
		GridBagConstraints gbc_btnStepOver = new GridBagConstraints();
		gbc_btnStepOver.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnStepOver.insets = new Insets(0, 0, 5, 0);
		gbc_btnStepOver.gridx = 0;
		gbc_btnStepOver.gridy = 1;
		panel.add(btnStepOver, gbc_btnStepOver);
		
		JButton btnPause = new JButton("Pause");
		GridBagConstraints gbc_btnPause = new GridBagConstraints();
		gbc_btnPause.insets = new Insets(0, 0, 5, 0);
		gbc_btnPause.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnPause.gridx = 0;
		gbc_btnPause.gridy = 2;
		panel.add(btnPause, gbc_btnPause);
		
		JButton btnRun = new JButton("Run");
		GridBagConstraints gbc_btnRun = new GridBagConstraints();
		gbc_btnRun.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnRun.gridx = 0;
		gbc_btnRun.gridy = 3;
		panel.add(btnRun, gbc_btnRun);
		
		JTabbedPane tabbedPane = new JTabbedPane(SwingConstants.TOP);
		GridBagConstraints gbc_tabbedPane = new GridBagConstraints();
		gbc_tabbedPane.fill = GridBagConstraints.BOTH;
		gbc_tabbedPane.gridx = 1;
		gbc_tabbedPane.gridy = 0;
		add(tabbedPane, gbc_tabbedPane);
		
		JPanel panel_4 = new JPanel();
		tabbedPane.addTab("CPU & Registers", null, panel_4, null);
		GridBagLayout gbl_panel_4 = new GridBagLayout();
		gbl_panel_4.columnWidths = new int[]{143, 0};
		gbl_panel_4.rowHeights = new int[]{560, 0};
		gbl_panel_4.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_4.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		panel_4.setLayout(gbl_panel_4);
		
		JPanel panel_5 = new JPanel();
		GridBagConstraints gbc_panel_5 = new GridBagConstraints();
		gbc_panel_5.fill = GridBagConstraints.BOTH;
		gbc_panel_5.gridx = 0;
		gbc_panel_5.gridy = 0;
		panel_4.add(panel_5, gbc_panel_5);
		GridBagLayout gbl_panel_5 = new GridBagLayout();
		gbl_panel_5.columnWidths = new int[]{0, 105, 17, 0, 105, 0};
		gbl_panel_5.rowHeights = new int[]{0, 0, 25, 0, 0, 25, 0, 0, 0, 25, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panel_5.columnWeights = new double[]{0.0, 1.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_5.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_5.setLayout(gbl_panel_5);
		
		JLabel lblr = new JLabel("$r0");
		GridBagConstraints gbc_lblr = new GridBagConstraints();
		gbc_lblr.insets = new Insets(0, 0, 5, 5);
		gbc_lblr.anchor = GridBagConstraints.EAST;
		gbc_lblr.gridx = 0;
		gbc_lblr.gridy = 0;
		panel_5.add(lblr, gbc_lblr);
		
		textField_3 = new JTextField();
		GridBagConstraints gbc_textField_3 = new GridBagConstraints();
		gbc_textField_3.insets = new Insets(0, 0, 5, 5);
		gbc_textField_3.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_3.gridx = 1;
		gbc_textField_3.gridy = 0;
		panel_5.add(textField_3, gbc_textField_3);
		textField_3.setColumns(10);
		
		JSeparator separator_3 = new JSeparator();
		separator_3.setOrientation(SwingConstants.VERTICAL);
		GridBagConstraints gbc_separator_3 = new GridBagConstraints();
		gbc_separator_3.fill = GridBagConstraints.VERTICAL;
		gbc_separator_3.gridheight = 21;
		gbc_separator_3.insets = new Insets(0, 0, 0, 5);
		gbc_separator_3.gridx = 2;
		gbc_separator_3.gridy = 0;
		panel_5.add(separator_3, gbc_separator_3);
		
		JLabel lbls = new JLabel("$s0");
		GridBagConstraints gbc_lbls = new GridBagConstraints();
		gbc_lbls.anchor = GridBagConstraints.EAST;
		gbc_lbls.insets = new Insets(0, 0, 5, 5);
		gbc_lbls.gridx = 3;
		gbc_lbls.gridy = 0;
		panel_5.add(lbls, gbc_lbls);
		
		textField_13 = new JTextField();
		GridBagConstraints gbc_textField_13 = new GridBagConstraints();
		gbc_textField_13.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_13.insets = new Insets(0, 0, 5, 0);
		gbc_textField_13.gridx = 4;
		gbc_textField_13.gridy = 0;
		panel_5.add(textField_13, gbc_textField_13);
		textField_13.setColumns(10);
		
		JLabel lblat = new JLabel("$at");
		GridBagConstraints gbc_lblat = new GridBagConstraints();
		gbc_lblat.anchor = GridBagConstraints.EAST;
		gbc_lblat.insets = new Insets(0, 0, 5, 5);
		gbc_lblat.gridx = 0;
		gbc_lblat.gridy = 1;
		panel_5.add(lblat, gbc_lblat);
		
		textField_4 = new JTextField();
		GridBagConstraints gbc_textField_4 = new GridBagConstraints();
		gbc_textField_4.insets = new Insets(0, 0, 5, 5);
		gbc_textField_4.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_4.gridx = 1;
		gbc_textField_4.gridy = 1;
		panel_5.add(textField_4, gbc_textField_4);
		textField_4.setColumns(10);
		
		JLabel lbls_1 = new JLabel("$s1");
		GridBagConstraints gbc_lbls_1 = new GridBagConstraints();
		gbc_lbls_1.anchor = GridBagConstraints.EAST;
		gbc_lbls_1.insets = new Insets(0, 0, 5, 5);
		gbc_lbls_1.gridx = 3;
		gbc_lbls_1.gridy = 1;
		panel_5.add(lbls_1, gbc_lbls_1);
		
		textField_14 = new JTextField();
		GridBagConstraints gbc_textField_14 = new GridBagConstraints();
		gbc_textField_14.insets = new Insets(0, 0, 5, 0);
		gbc_textField_14.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_14.gridx = 4;
		gbc_textField_14.gridy = 1;
		panel_5.add(textField_14, gbc_textField_14);
		textField_14.setColumns(10);
		
		JSeparator separator = new JSeparator();
		GridBagConstraints gbc_separator = new GridBagConstraints();
		gbc_separator.gridwidth = 2;
		gbc_separator.fill = GridBagConstraints.HORIZONTAL;
		gbc_separator.insets = new Insets(0, 0, 5, 5);
		gbc_separator.gridx = 0;
		gbc_separator.gridy = 2;
		panel_5.add(separator, gbc_separator);
		
		JLabel lbls_2 = new JLabel("$s2");
		GridBagConstraints gbc_lbls_2 = new GridBagConstraints();
		gbc_lbls_2.anchor = GridBagConstraints.EAST;
		gbc_lbls_2.insets = new Insets(0, 0, 5, 5);
		gbc_lbls_2.gridx = 3;
		gbc_lbls_2.gridy = 2;
		panel_5.add(lbls_2, gbc_lbls_2);
		
		textField_15 = new JTextField();
		GridBagConstraints gbc_textField_15 = new GridBagConstraints();
		gbc_textField_15.insets = new Insets(0, 0, 5, 0);
		gbc_textField_15.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_15.gridx = 4;
		gbc_textField_15.gridy = 2;
		panel_5.add(textField_15, gbc_textField_15);
		textField_15.setColumns(10);
		
		JLabel lblv = new JLabel("$v0");
		GridBagConstraints gbc_lblv = new GridBagConstraints();
		gbc_lblv.anchor = GridBagConstraints.EAST;
		gbc_lblv.insets = new Insets(0, 0, 5, 5);
		gbc_lblv.gridx = 0;
		gbc_lblv.gridy = 3;
		panel_5.add(lblv, gbc_lblv);
		
		textField_5 = new JTextField();
		GridBagConstraints gbc_textField_5 = new GridBagConstraints();
		gbc_textField_5.insets = new Insets(0, 0, 5, 5);
		gbc_textField_5.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_5.gridx = 1;
		gbc_textField_5.gridy = 3;
		panel_5.add(textField_5, gbc_textField_5);
		textField_5.setColumns(10);
		
		JLabel lbls_3 = new JLabel("$s3");
		GridBagConstraints gbc_lbls_3 = new GridBagConstraints();
		gbc_lbls_3.anchor = GridBagConstraints.EAST;
		gbc_lbls_3.insets = new Insets(0, 0, 5, 5);
		gbc_lbls_3.gridx = 3;
		gbc_lbls_3.gridy = 3;
		panel_5.add(lbls_3, gbc_lbls_3);
		
		textField_16 = new JTextField();
		GridBagConstraints gbc_textField_16 = new GridBagConstraints();
		gbc_textField_16.insets = new Insets(0, 0, 5, 0);
		gbc_textField_16.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_16.gridx = 4;
		gbc_textField_16.gridy = 3;
		panel_5.add(textField_16, gbc_textField_16);
		textField_16.setColumns(10);
		
		JLabel lblv_1 = new JLabel("$v1");
		GridBagConstraints gbc_lblv_1 = new GridBagConstraints();
		gbc_lblv_1.anchor = GridBagConstraints.EAST;
		gbc_lblv_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblv_1.gridx = 0;
		gbc_lblv_1.gridy = 4;
		panel_5.add(lblv_1, gbc_lblv_1);
		
		textField_6 = new JTextField();
		GridBagConstraints gbc_textField_6 = new GridBagConstraints();
		gbc_textField_6.insets = new Insets(0, 0, 5, 5);
		gbc_textField_6.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_6.gridx = 1;
		gbc_textField_6.gridy = 4;
		panel_5.add(textField_6, gbc_textField_6);
		textField_6.setColumns(10);
		
		JLabel lbls_4 = new JLabel("$s4");
		GridBagConstraints gbc_lbls_4 = new GridBagConstraints();
		gbc_lbls_4.anchor = GridBagConstraints.EAST;
		gbc_lbls_4.insets = new Insets(0, 0, 5, 5);
		gbc_lbls_4.gridx = 3;
		gbc_lbls_4.gridy = 4;
		panel_5.add(lbls_4, gbc_lbls_4);
		
		textField_17 = new JTextField();
		GridBagConstraints gbc_textField_17 = new GridBagConstraints();
		gbc_textField_17.insets = new Insets(0, 0, 5, 0);
		gbc_textField_17.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_17.gridx = 4;
		gbc_textField_17.gridy = 4;
		panel_5.add(textField_17, gbc_textField_17);
		textField_17.setColumns(10);
		
		JSeparator separator_1 = new JSeparator();
		GridBagConstraints gbc_separator_1 = new GridBagConstraints();
		gbc_separator_1.fill = GridBagConstraints.HORIZONTAL;
		gbc_separator_1.gridwidth = 2;
		gbc_separator_1.insets = new Insets(0, 0, 5, 5);
		gbc_separator_1.gridx = 0;
		gbc_separator_1.gridy = 5;
		panel_5.add(separator_1, gbc_separator_1);
		
		JLabel lbls_5 = new JLabel("$s5");
		GridBagConstraints gbc_lbls_5 = new GridBagConstraints();
		gbc_lbls_5.anchor = GridBagConstraints.EAST;
		gbc_lbls_5.insets = new Insets(0, 0, 5, 5);
		gbc_lbls_5.gridx = 3;
		gbc_lbls_5.gridy = 5;
		panel_5.add(lbls_5, gbc_lbls_5);
		
		textField_18 = new JTextField();
		GridBagConstraints gbc_textField_18 = new GridBagConstraints();
		gbc_textField_18.insets = new Insets(0, 0, 5, 0);
		gbc_textField_18.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_18.gridx = 4;
		gbc_textField_18.gridy = 5;
		panel_5.add(textField_18, gbc_textField_18);
		textField_18.setColumns(10);
		
		JLabel lbla = new JLabel("$a0");
		GridBagConstraints gbc_lbla = new GridBagConstraints();
		gbc_lbla.anchor = GridBagConstraints.EAST;
		gbc_lbla.insets = new Insets(0, 0, 5, 5);
		gbc_lbla.gridx = 0;
		gbc_lbla.gridy = 6;
		panel_5.add(lbla, gbc_lbla);
		
		textField_7 = new JTextField();
		GridBagConstraints gbc_textField_7 = new GridBagConstraints();
		gbc_textField_7.insets = new Insets(0, 0, 5, 5);
		gbc_textField_7.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_7.gridx = 1;
		gbc_textField_7.gridy = 6;
		panel_5.add(textField_7, gbc_textField_7);
		textField_7.setColumns(10);
		
		JLabel lbls_6 = new JLabel("$s6");
		GridBagConstraints gbc_lbls_6 = new GridBagConstraints();
		gbc_lbls_6.anchor = GridBagConstraints.EAST;
		gbc_lbls_6.insets = new Insets(0, 0, 5, 5);
		gbc_lbls_6.gridx = 3;
		gbc_lbls_6.gridy = 6;
		panel_5.add(lbls_6, gbc_lbls_6);
		
		textField_19 = new JTextField();
		GridBagConstraints gbc_textField_19 = new GridBagConstraints();
		gbc_textField_19.insets = new Insets(0, 0, 5, 0);
		gbc_textField_19.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_19.gridx = 4;
		gbc_textField_19.gridy = 6;
		panel_5.add(textField_19, gbc_textField_19);
		textField_19.setColumns(10);
		
		JLabel lbla_1 = new JLabel("$a1");
		GridBagConstraints gbc_lbla_1 = new GridBagConstraints();
		gbc_lbla_1.anchor = GridBagConstraints.EAST;
		gbc_lbla_1.insets = new Insets(0, 0, 5, 5);
		gbc_lbla_1.gridx = 0;
		gbc_lbla_1.gridy = 7;
		panel_5.add(lbla_1, gbc_lbla_1);
		
		textField_8 = new JTextField();
		GridBagConstraints gbc_textField_8 = new GridBagConstraints();
		gbc_textField_8.insets = new Insets(0, 0, 5, 5);
		gbc_textField_8.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_8.gridx = 1;
		gbc_textField_8.gridy = 7;
		panel_5.add(textField_8, gbc_textField_8);
		textField_8.setColumns(10);
		
		JLabel lbls_7 = new JLabel("$s7");
		GridBagConstraints gbc_lbls_7 = new GridBagConstraints();
		gbc_lbls_7.anchor = GridBagConstraints.EAST;
		gbc_lbls_7.insets = new Insets(0, 0, 5, 5);
		gbc_lbls_7.gridx = 3;
		gbc_lbls_7.gridy = 7;
		panel_5.add(lbls_7, gbc_lbls_7);
		
		textField_20 = new JTextField();
		GridBagConstraints gbc_textField_20 = new GridBagConstraints();
		gbc_textField_20.insets = new Insets(0, 0, 5, 0);
		gbc_textField_20.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_20.gridx = 4;
		gbc_textField_20.gridy = 7;
		panel_5.add(textField_20, gbc_textField_20);
		textField_20.setColumns(10);
		
		JLabel lbla_2 = new JLabel("$a2");
		GridBagConstraints gbc_lbla_2 = new GridBagConstraints();
		gbc_lbla_2.anchor = GridBagConstraints.EAST;
		gbc_lbla_2.insets = new Insets(0, 0, 5, 5);
		gbc_lbla_2.gridx = 0;
		gbc_lbla_2.gridy = 8;
		panel_5.add(lbla_2, gbc_lbla_2);
		
		textField_9 = new JTextField();
		GridBagConstraints gbc_textField_9 = new GridBagConstraints();
		gbc_textField_9.insets = new Insets(0, 0, 5, 5);
		gbc_textField_9.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_9.gridx = 1;
		gbc_textField_9.gridy = 8;
		panel_5.add(textField_9, gbc_textField_9);
		textField_9.setColumns(10);
		
		JLabel lbls_8 = new JLabel("$s8");
		GridBagConstraints gbc_lbls_8 = new GridBagConstraints();
		gbc_lbls_8.anchor = GridBagConstraints.EAST;
		gbc_lbls_8.insets = new Insets(0, 0, 5, 5);
		gbc_lbls_8.gridx = 3;
		gbc_lbls_8.gridy = 8;
		panel_5.add(lbls_8, gbc_lbls_8);
		
		textField_21 = new JTextField();
		GridBagConstraints gbc_textField_21 = new GridBagConstraints();
		gbc_textField_21.insets = new Insets(0, 0, 5, 0);
		gbc_textField_21.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_21.gridx = 4;
		gbc_textField_21.gridy = 8;
		panel_5.add(textField_21, gbc_textField_21);
		textField_21.setColumns(10);
		
		JLabel lbla_3 = new JLabel("$a3");
		GridBagConstraints gbc_lbla_3 = new GridBagConstraints();
		gbc_lbla_3.anchor = GridBagConstraints.EAST;
		gbc_lbla_3.insets = new Insets(0, 0, 5, 5);
		gbc_lbla_3.gridx = 0;
		gbc_lbla_3.gridy = 9;
		panel_5.add(lbla_3, gbc_lbla_3);
		
		textField_10 = new JTextField();
		GridBagConstraints gbc_textField_10 = new GridBagConstraints();
		gbc_textField_10.insets = new Insets(0, 0, 5, 5);
		gbc_textField_10.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_10.gridx = 1;
		gbc_textField_10.gridy = 9;
		panel_5.add(textField_10, gbc_textField_10);
		textField_10.setColumns(10);
		
		JSeparator separator_4 = new JSeparator();
		GridBagConstraints gbc_separator_4 = new GridBagConstraints();
		gbc_separator_4.gridwidth = 2;
		gbc_separator_4.fill = GridBagConstraints.HORIZONTAL;
		gbc_separator_4.insets = new Insets(0, 0, 5, 0);
		gbc_separator_4.gridx = 3;
		gbc_separator_4.gridy = 9;
		panel_5.add(separator_4, gbc_separator_4);
		
		JSeparator separator_2 = new JSeparator();
		GridBagConstraints gbc_separator_2 = new GridBagConstraints();
		gbc_separator_2.insets = new Insets(0, 0, 5, 5);
		gbc_separator_2.fill = GridBagConstraints.HORIZONTAL;
		gbc_separator_2.gridwidth = 2;
		gbc_separator_2.gridx = 0;
		gbc_separator_2.gridy = 10;
		panel_5.add(separator_2, gbc_separator_2);
		
		JLabel lblk = new JLabel("$k0");
		GridBagConstraints gbc_lblk = new GridBagConstraints();
		gbc_lblk.anchor = GridBagConstraints.EAST;
		gbc_lblk.insets = new Insets(0, 0, 5, 5);
		gbc_lblk.gridx = 3;
		gbc_lblk.gridy = 10;
		panel_5.add(lblk, gbc_lblk);
		
		textField_22 = new JTextField();
		GridBagConstraints gbc_textField_22 = new GridBagConstraints();
		gbc_textField_22.insets = new Insets(0, 0, 5, 0);
		gbc_textField_22.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_22.gridx = 4;
		gbc_textField_22.gridy = 10;
		panel_5.add(textField_22, gbc_textField_22);
		textField_22.setColumns(10);
		
		JLabel lblt = new JLabel("$t0");
		GridBagConstraints gbc_lblt = new GridBagConstraints();
		gbc_lblt.anchor = GridBagConstraints.EAST;
		gbc_lblt.insets = new Insets(0, 0, 5, 5);
		gbc_lblt.gridx = 0;
		gbc_lblt.gridy = 11;
		panel_5.add(lblt, gbc_lblt);
		
		textField_11 = new JTextField();
		GridBagConstraints gbc_textField_11 = new GridBagConstraints();
		gbc_textField_11.insets = new Insets(0, 0, 5, 5);
		gbc_textField_11.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_11.gridx = 1;
		gbc_textField_11.gridy = 11;
		panel_5.add(textField_11, gbc_textField_11);
		textField_11.setColumns(10);
		
		JLabel lblk_1 = new JLabel("$k1");
		GridBagConstraints gbc_lblk_1 = new GridBagConstraints();
		gbc_lblk_1.anchor = GridBagConstraints.EAST;
		gbc_lblk_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblk_1.gridx = 3;
		gbc_lblk_1.gridy = 11;
		panel_5.add(lblk_1, gbc_lblk_1);
		
		textField_23 = new JTextField();
		GridBagConstraints gbc_textField_23 = new GridBagConstraints();
		gbc_textField_23.insets = new Insets(0, 0, 5, 0);
		gbc_textField_23.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_23.gridx = 4;
		gbc_textField_23.gridy = 11;
		panel_5.add(textField_23, gbc_textField_23);
		textField_23.setColumns(10);
		
		JLabel lblt_1 = new JLabel("$t1");
		GridBagConstraints gbc_lblt_1 = new GridBagConstraints();
		gbc_lblt_1.anchor = GridBagConstraints.EAST;
		gbc_lblt_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblt_1.gridx = 0;
		gbc_lblt_1.gridy = 12;
		panel_5.add(lblt_1, gbc_lblt_1);
		
		textField_12 = new JTextField();
		GridBagConstraints gbc_textField_12 = new GridBagConstraints();
		gbc_textField_12.insets = new Insets(0, 0, 5, 5);
		gbc_textField_12.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_12.gridx = 1;
		gbc_textField_12.gridy = 12;
		panel_5.add(textField_12, gbc_textField_12);
		textField_12.setColumns(10);
		
		JSeparator separator_5 = new JSeparator();
		GridBagConstraints gbc_separator_5 = new GridBagConstraints();
		gbc_separator_5.fill = GridBagConstraints.HORIZONTAL;
		gbc_separator_5.gridwidth = 2;
		gbc_separator_5.insets = new Insets(0, 0, 5, 0);
		gbc_separator_5.gridx = 3;
		gbc_separator_5.gridy = 12;
		panel_5.add(separator_5, gbc_separator_5);
		
		JLabel lblt_2 = new JLabel("$t2");
		GridBagConstraints gbc_lblt_2 = new GridBagConstraints();
		gbc_lblt_2.anchor = GridBagConstraints.EAST;
		gbc_lblt_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblt_2.gridx = 0;
		gbc_lblt_2.gridy = 13;
		panel_5.add(lblt_2, gbc_lblt_2);
		
		textField_24 = new JTextField();
		GridBagConstraints gbc_textField_24 = new GridBagConstraints();
		gbc_textField_24.insets = new Insets(0, 0, 5, 5);
		gbc_textField_24.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_24.gridx = 1;
		gbc_textField_24.gridy = 13;
		panel_5.add(textField_24, gbc_textField_24);
		textField_24.setColumns(10);
		
		JLabel lblgp = new JLabel("$gp");
		GridBagConstraints gbc_lblgp = new GridBagConstraints();
		gbc_lblgp.anchor = GridBagConstraints.EAST;
		gbc_lblgp.insets = new Insets(0, 0, 5, 5);
		gbc_lblgp.gridx = 3;
		gbc_lblgp.gridy = 13;
		panel_5.add(lblgp, gbc_lblgp);
		
		textField_32 = new JTextField();
		GridBagConstraints gbc_textField_32 = new GridBagConstraints();
		gbc_textField_32.insets = new Insets(0, 0, 5, 0);
		gbc_textField_32.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_32.gridx = 4;
		gbc_textField_32.gridy = 13;
		panel_5.add(textField_32, gbc_textField_32);
		textField_32.setColumns(10);
		
		JLabel lblt_3 = new JLabel("$t3");
		GridBagConstraints gbc_lblt_3 = new GridBagConstraints();
		gbc_lblt_3.anchor = GridBagConstraints.EAST;
		gbc_lblt_3.insets = new Insets(0, 0, 5, 5);
		gbc_lblt_3.gridx = 0;
		gbc_lblt_3.gridy = 14;
		panel_5.add(lblt_3, gbc_lblt_3);
		
		textField_25 = new JTextField();
		GridBagConstraints gbc_textField_25 = new GridBagConstraints();
		gbc_textField_25.insets = new Insets(0, 0, 5, 5);
		gbc_textField_25.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_25.gridx = 1;
		gbc_textField_25.gridy = 14;
		panel_5.add(textField_25, gbc_textField_25);
		textField_25.setColumns(10);
		
		JLabel lblsp = new JLabel("$sp");
		GridBagConstraints gbc_lblsp = new GridBagConstraints();
		gbc_lblsp.anchor = GridBagConstraints.EAST;
		gbc_lblsp.insets = new Insets(0, 0, 5, 5);
		gbc_lblsp.gridx = 3;
		gbc_lblsp.gridy = 14;
		panel_5.add(lblsp, gbc_lblsp);
		
		textField_33 = new JTextField();
		GridBagConstraints gbc_textField_33 = new GridBagConstraints();
		gbc_textField_33.insets = new Insets(0, 0, 5, 0);
		gbc_textField_33.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_33.gridx = 4;
		gbc_textField_33.gridy = 14;
		panel_5.add(textField_33, gbc_textField_33);
		textField_33.setColumns(10);
		
		JLabel lblt_4 = new JLabel("$t4");
		GridBagConstraints gbc_lblt_4 = new GridBagConstraints();
		gbc_lblt_4.anchor = GridBagConstraints.EAST;
		gbc_lblt_4.insets = new Insets(0, 0, 5, 5);
		gbc_lblt_4.gridx = 0;
		gbc_lblt_4.gridy = 15;
		panel_5.add(lblt_4, gbc_lblt_4);
		
		textField_26 = new JTextField();
		GridBagConstraints gbc_textField_26 = new GridBagConstraints();
		gbc_textField_26.insets = new Insets(0, 0, 5, 5);
		gbc_textField_26.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_26.gridx = 1;
		gbc_textField_26.gridy = 15;
		panel_5.add(textField_26, gbc_textField_26);
		textField_26.setColumns(10);
		
		JSeparator separator_6 = new JSeparator();
		GridBagConstraints gbc_separator_6 = new GridBagConstraints();
		gbc_separator_6.fill = GridBagConstraints.HORIZONTAL;
		gbc_separator_6.gridwidth = 2;
		gbc_separator_6.insets = new Insets(0, 0, 5, 0);
		gbc_separator_6.gridx = 3;
		gbc_separator_6.gridy = 15;
		panel_5.add(separator_6, gbc_separator_6);
		
		JLabel lblt_5 = new JLabel("$t5");
		GridBagConstraints gbc_lblt_5 = new GridBagConstraints();
		gbc_lblt_5.anchor = GridBagConstraints.EAST;
		gbc_lblt_5.insets = new Insets(0, 0, 5, 5);
		gbc_lblt_5.gridx = 0;
		gbc_lblt_5.gridy = 16;
		panel_5.add(lblt_5, gbc_lblt_5);
		
		textField_27 = new JTextField();
		GridBagConstraints gbc_textField_27 = new GridBagConstraints();
		gbc_textField_27.insets = new Insets(0, 0, 5, 5);
		gbc_textField_27.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_27.gridx = 1;
		gbc_textField_27.gridy = 16;
		panel_5.add(textField_27, gbc_textField_27);
		textField_27.setColumns(10);
		
		JLabel lblra = new JLabel("$ra");
		GridBagConstraints gbc_lblra = new GridBagConstraints();
		gbc_lblra.anchor = GridBagConstraints.EAST;
		gbc_lblra.insets = new Insets(0, 0, 5, 5);
		gbc_lblra.gridx = 3;
		gbc_lblra.gridy = 16;
		panel_5.add(lblra, gbc_lblra);
		
		textField_34 = new JTextField();
		GridBagConstraints gbc_textField_34 = new GridBagConstraints();
		gbc_textField_34.insets = new Insets(0, 0, 5, 0);
		gbc_textField_34.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_34.gridx = 4;
		gbc_textField_34.gridy = 16;
		panel_5.add(textField_34, gbc_textField_34);
		textField_34.setColumns(10);
		
		JLabel lblt_6 = new JLabel("$t6");
		GridBagConstraints gbc_lblt_6 = new GridBagConstraints();
		gbc_lblt_6.anchor = GridBagConstraints.EAST;
		gbc_lblt_6.insets = new Insets(0, 0, 5, 5);
		gbc_lblt_6.gridx = 0;
		gbc_lblt_6.gridy = 17;
		panel_5.add(lblt_6, gbc_lblt_6);
		
		textField_28 = new JTextField();
		GridBagConstraints gbc_textField_28 = new GridBagConstraints();
		gbc_textField_28.insets = new Insets(0, 0, 5, 5);
		gbc_textField_28.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_28.gridx = 1;
		gbc_textField_28.gridy = 17;
		panel_5.add(textField_28, gbc_textField_28);
		textField_28.setColumns(10);
		
		JSeparator separator_7 = new JSeparator();
		GridBagConstraints gbc_separator_7 = new GridBagConstraints();
		gbc_separator_7.fill = GridBagConstraints.HORIZONTAL;
		gbc_separator_7.gridwidth = 2;
		gbc_separator_7.insets = new Insets(0, 0, 5, 0);
		gbc_separator_7.gridx = 3;
		gbc_separator_7.gridy = 17;
		panel_5.add(separator_7, gbc_separator_7);
		
		JLabel lblt_7 = new JLabel("$t7");
		GridBagConstraints gbc_lblt_7 = new GridBagConstraints();
		gbc_lblt_7.anchor = GridBagConstraints.EAST;
		gbc_lblt_7.insets = new Insets(0, 0, 5, 5);
		gbc_lblt_7.gridx = 0;
		gbc_lblt_7.gridy = 18;
		panel_5.add(lblt_7, gbc_lblt_7);
		
		textField_29 = new JTextField();
		GridBagConstraints gbc_textField_29 = new GridBagConstraints();
		gbc_textField_29.insets = new Insets(0, 0, 5, 5);
		gbc_textField_29.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_29.gridx = 1;
		gbc_textField_29.gridy = 18;
		panel_5.add(textField_29, gbc_textField_29);
		textField_29.setColumns(10);
		
		JLabel lblPc = new JLabel("$pc");
		GridBagConstraints gbc_lblPc = new GridBagConstraints();
		gbc_lblPc.insets = new Insets(0, 0, 5, 5);
		gbc_lblPc.gridx = 3;
		gbc_lblPc.gridy = 18;
		panel_5.add(lblPc, gbc_lblPc);
		
		textField = new JTextField();
		GridBagConstraints gbc_textField = new GridBagConstraints();
		gbc_textField.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField.insets = new Insets(0, 0, 5, 0);
		gbc_textField.gridx = 4;
		gbc_textField.gridy = 18;
		panel_5.add(textField, gbc_textField);
		textField.setColumns(10);
		
		JLabel lblt_8 = new JLabel("$t8");
		GridBagConstraints gbc_lblt_8 = new GridBagConstraints();
		gbc_lblt_8.anchor = GridBagConstraints.EAST;
		gbc_lblt_8.insets = new Insets(0, 0, 5, 5);
		gbc_lblt_8.gridx = 0;
		gbc_lblt_8.gridy = 19;
		panel_5.add(lblt_8, gbc_lblt_8);
		
		textField_30 = new JTextField();
		GridBagConstraints gbc_textField_30 = new GridBagConstraints();
		gbc_textField_30.insets = new Insets(0, 0, 5, 5);
		gbc_textField_30.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_30.gridx = 1;
		gbc_textField_30.gridy = 19;
		panel_5.add(textField_30, gbc_textField_30);
		textField_30.setColumns(10);
		
		JLabel lbllo = new JLabel("$Lo");
		GridBagConstraints gbc_lbllo = new GridBagConstraints();
		gbc_lbllo.insets = new Insets(0, 0, 5, 5);
		gbc_lbllo.gridx = 3;
		gbc_lbllo.gridy = 19;
		panel_5.add(lbllo, gbc_lbllo);
		
		textField_1 = new JTextField();
		GridBagConstraints gbc_textField_1 = new GridBagConstraints();
		gbc_textField_1.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_1.insets = new Insets(0, 0, 5, 0);
		gbc_textField_1.gridx = 4;
		gbc_textField_1.gridy = 19;
		panel_5.add(textField_1, gbc_textField_1);
		textField_1.setColumns(10);
		
		JLabel lblt_9 = new JLabel("$t9");
		GridBagConstraints gbc_lblt_9 = new GridBagConstraints();
		gbc_lblt_9.anchor = GridBagConstraints.EAST;
		gbc_lblt_9.insets = new Insets(0, 0, 0, 5);
		gbc_lblt_9.gridx = 0;
		gbc_lblt_9.gridy = 20;
		panel_5.add(lblt_9, gbc_lblt_9);
		
		textField_31 = new JTextField();
		GridBagConstraints gbc_textField_31 = new GridBagConstraints();
		gbc_textField_31.insets = new Insets(0, 0, 0, 5);
		gbc_textField_31.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_31.gridx = 1;
		gbc_textField_31.gridy = 20;
		panel_5.add(textField_31, gbc_textField_31);
		textField_31.setColumns(10);
		
		JLabel lblhi = new JLabel("$Hi");
		GridBagConstraints gbc_lblhi = new GridBagConstraints();
		gbc_lblhi.insets = new Insets(0, 0, 0, 5);
		gbc_lblhi.gridx = 3;
		gbc_lblhi.gridy = 20;
		panel_5.add(lblhi, gbc_lblhi);
		
		textField_2 = new JTextField();
		GridBagConstraints gbc_textField_2 = new GridBagConstraints();
		gbc_textField_2.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_2.gridx = 4;
		gbc_textField_2.gridy = 20;
		panel_5.add(textField_2, gbc_textField_2);
		textField_2.setColumns(10);
		
		JPanel panel_1 = new JPanel();
		tabbedPane.addTab("COP0", null, panel_1, null);
		GridBagLayout gbl_panel_1 = new GridBagLayout();
		gbl_panel_1.columnWidths = new int[]{0, 0};
		gbl_panel_1.rowHeights = new int[]{512, 0};
		gbl_panel_1.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_1.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		panel_1.setLayout(gbl_panel_1);
		
		JPanel panel_7 = new JPanel();
		GridBagConstraints gbc_panel_7 = new GridBagConstraints();
		gbc_panel_7.fill = GridBagConstraints.BOTH;
		gbc_panel_7.gridx = 0;
		gbc_panel_7.gridy = 0;
		panel_1.add(panel_7, gbc_panel_7);
		GridBagLayout gbl_panel_7 = new GridBagLayout();
		gbl_panel_7.columnWidths = new int[]{0, 101, 0, 59, 0};
		gbl_panel_7.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panel_7.columnWeights = new double[]{0.0, 1.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_7.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_7.setLayout(gbl_panel_7);
		
		JLabel lblIndex = new JLabel("Index");
		GridBagConstraints gbc_lblIndex = new GridBagConstraints();
		gbc_lblIndex.anchor = GridBagConstraints.EAST;
		gbc_lblIndex.insets = new Insets(0, 0, 5, 5);
		gbc_lblIndex.gridx = 0;
		gbc_lblIndex.gridy = 0;
		panel_7.add(lblIndex, gbc_lblIndex);
		
		textField_35 = new JTextField();
		GridBagConstraints gbc_textField_35 = new GridBagConstraints();
		gbc_textField_35.insets = new Insets(0, 0, 5, 5);
		gbc_textField_35.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_35.gridx = 1;
		gbc_textField_35.gridy = 0;
		panel_7.add(textField_35, gbc_textField_35);
		textField_35.setColumns(10);
		
		JLabel lblConfig = new JLabel("Config");
		GridBagConstraints gbc_lblConfig = new GridBagConstraints();
		gbc_lblConfig.anchor = GridBagConstraints.EAST;
		gbc_lblConfig.insets = new Insets(0, 0, 5, 5);
		gbc_lblConfig.gridx = 2;
		gbc_lblConfig.gridy = 0;
		panel_7.add(lblConfig, gbc_lblConfig);
		
		textField_36 = new JTextField();
		GridBagConstraints gbc_textField_36 = new GridBagConstraints();
		gbc_textField_36.insets = new Insets(0, 0, 5, 0);
		gbc_textField_36.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_36.gridx = 3;
		gbc_textField_36.gridy = 0;
		panel_7.add(textField_36, gbc_textField_36);
		textField_36.setColumns(10);
		
		JLabel lblRandom = new JLabel("Random");
		GridBagConstraints gbc_lblRandom = new GridBagConstraints();
		gbc_lblRandom.anchor = GridBagConstraints.EAST;
		gbc_lblRandom.insets = new Insets(0, 0, 5, 5);
		gbc_lblRandom.gridx = 0;
		gbc_lblRandom.gridy = 1;
		panel_7.add(lblRandom, gbc_lblRandom);
		
		textField_37 = new JTextField();
		GridBagConstraints gbc_textField_37 = new GridBagConstraints();
		gbc_textField_37.insets = new Insets(0, 0, 5, 5);
		gbc_textField_37.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_37.gridx = 1;
		gbc_textField_37.gridy = 1;
		panel_7.add(textField_37, gbc_textField_37);
		textField_37.setColumns(10);
		
		JLabel lblLladdr = new JLabel("LLAddr");
		GridBagConstraints gbc_lblLladdr = new GridBagConstraints();
		gbc_lblLladdr.anchor = GridBagConstraints.EAST;
		gbc_lblLladdr.insets = new Insets(0, 0, 5, 5);
		gbc_lblLladdr.gridx = 2;
		gbc_lblLladdr.gridy = 1;
		panel_7.add(lblLladdr, gbc_lblLladdr);
		
		textField_52 = new JTextField();
		GridBagConstraints gbc_textField_52 = new GridBagConstraints();
		gbc_textField_52.insets = new Insets(0, 0, 5, 0);
		gbc_textField_52.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_52.gridx = 3;
		gbc_textField_52.gridy = 1;
		panel_7.add(textField_52, gbc_textField_52);
		textField_52.setColumns(10);
		
		JLabel lblEntrylo = new JLabel("EntryLo0");
		GridBagConstraints gbc_lblEntrylo = new GridBagConstraints();
		gbc_lblEntrylo.insets = new Insets(0, 0, 5, 5);
		gbc_lblEntrylo.gridx = 0;
		gbc_lblEntrylo.gridy = 2;
		panel_7.add(lblEntrylo, gbc_lblEntrylo);
		
		textField_38 = new JTextField();
		GridBagConstraints gbc_textField_38 = new GridBagConstraints();
		gbc_textField_38.insets = new Insets(0, 0, 5, 5);
		gbc_textField_38.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_38.gridx = 1;
		gbc_textField_38.gridy = 2;
		panel_7.add(textField_38, gbc_textField_38);
		textField_38.setColumns(10);
		
		JLabel lblWatchlo = new JLabel("WatchLO");
		GridBagConstraints gbc_lblWatchlo = new GridBagConstraints();
		gbc_lblWatchlo.anchor = GridBagConstraints.EAST;
		gbc_lblWatchlo.insets = new Insets(0, 0, 5, 5);
		gbc_lblWatchlo.gridx = 2;
		gbc_lblWatchlo.gridy = 2;
		panel_7.add(lblWatchlo, gbc_lblWatchlo);
		
		textField_53 = new JTextField();
		GridBagConstraints gbc_textField_53 = new GridBagConstraints();
		gbc_textField_53.insets = new Insets(0, 0, 5, 0);
		gbc_textField_53.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_53.gridx = 3;
		gbc_textField_53.gridy = 2;
		panel_7.add(textField_53, gbc_textField_53);
		textField_53.setColumns(10);
		
		JLabel lblBpc = new JLabel("BPC");
		GridBagConstraints gbc_lblBpc = new GridBagConstraints();
		gbc_lblBpc.anchor = GridBagConstraints.EAST;
		gbc_lblBpc.insets = new Insets(0, 0, 5, 5);
		gbc_lblBpc.gridx = 0;
		gbc_lblBpc.gridy = 3;
		panel_7.add(lblBpc, gbc_lblBpc);
		
		textField_39 = new JTextField();
		GridBagConstraints gbc_textField_39 = new GridBagConstraints();
		gbc_textField_39.insets = new Insets(0, 0, 5, 5);
		gbc_textField_39.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_39.gridx = 1;
		gbc_textField_39.gridy = 3;
		panel_7.add(textField_39, gbc_textField_39);
		textField_39.setColumns(10);
		
		JLabel lblWatchhi = new JLabel("WatchHI");
		GridBagConstraints gbc_lblWatchhi = new GridBagConstraints();
		gbc_lblWatchhi.anchor = GridBagConstraints.EAST;
		gbc_lblWatchhi.insets = new Insets(0, 0, 5, 5);
		gbc_lblWatchhi.gridx = 2;
		gbc_lblWatchhi.gridy = 3;
		panel_7.add(lblWatchhi, gbc_lblWatchhi);
		
		textField_54 = new JTextField();
		GridBagConstraints gbc_textField_54 = new GridBagConstraints();
		gbc_textField_54.insets = new Insets(0, 0, 5, 0);
		gbc_textField_54.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_54.gridx = 3;
		gbc_textField_54.gridy = 3;
		panel_7.add(textField_54, gbc_textField_54);
		textField_54.setColumns(10);
		
		JLabel lblContext = new JLabel("Context");
		GridBagConstraints gbc_lblContext = new GridBagConstraints();
		gbc_lblContext.anchor = GridBagConstraints.EAST;
		gbc_lblContext.insets = new Insets(0, 0, 5, 5);
		gbc_lblContext.gridx = 0;
		gbc_lblContext.gridy = 4;
		panel_7.add(lblContext, gbc_lblContext);
		
		textField_40 = new JTextField();
		GridBagConstraints gbc_textField_40 = new GridBagConstraints();
		gbc_textField_40.insets = new Insets(0, 0, 5, 5);
		gbc_textField_40.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_40.gridx = 1;
		gbc_textField_40.gridy = 4;
		panel_7.add(textField_40, gbc_textField_40);
		textField_40.setColumns(10);
		
		JLabel lblXcontext = new JLabel("XContext");
		GridBagConstraints gbc_lblXcontext = new GridBagConstraints();
		gbc_lblXcontext.anchor = GridBagConstraints.EAST;
		gbc_lblXcontext.insets = new Insets(0, 0, 5, 5);
		gbc_lblXcontext.gridx = 2;
		gbc_lblXcontext.gridy = 4;
		panel_7.add(lblXcontext, gbc_lblXcontext);
		
		textField_55 = new JTextField();
		GridBagConstraints gbc_textField_55 = new GridBagConstraints();
		gbc_textField_55.insets = new Insets(0, 0, 5, 0);
		gbc_textField_55.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_55.gridx = 3;
		gbc_textField_55.gridy = 4;
		panel_7.add(textField_55, gbc_textField_55);
		textField_55.setColumns(10);
		
		JLabel lblBda = new JLabel("BDA");
		GridBagConstraints gbc_lblBda = new GridBagConstraints();
		gbc_lblBda.anchor = GridBagConstraints.EAST;
		gbc_lblBda.insets = new Insets(0, 0, 5, 5);
		gbc_lblBda.gridx = 0;
		gbc_lblBda.gridy = 5;
		panel_7.add(lblBda, gbc_lblBda);
		
		textField_41 = new JTextField();
		GridBagConstraints gbc_textField_41 = new GridBagConstraints();
		gbc_textField_41.insets = new Insets(0, 0, 5, 5);
		gbc_textField_41.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_41.gridx = 1;
		gbc_textField_41.gridy = 5;
		panel_7.add(textField_41, gbc_textField_41);
		textField_41.setColumns(10);
		
		JLabel lblReserved = new JLabel("Reserved1");
		GridBagConstraints gbc_lblReserved = new GridBagConstraints();
		gbc_lblReserved.anchor = GridBagConstraints.EAST;
		gbc_lblReserved.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved.gridx = 2;
		gbc_lblReserved.gridy = 5;
		panel_7.add(lblReserved, gbc_lblReserved);
		
		textField_56 = new JTextField();
		GridBagConstraints gbc_textField_56 = new GridBagConstraints();
		gbc_textField_56.insets = new Insets(0, 0, 5, 0);
		gbc_textField_56.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_56.gridx = 3;
		gbc_textField_56.gridy = 5;
		panel_7.add(textField_56, gbc_textField_56);
		textField_56.setColumns(10);
		
		JLabel lblPidmask = new JLabel("PIDMask");
		GridBagConstraints gbc_lblPidmask = new GridBagConstraints();
		gbc_lblPidmask.anchor = GridBagConstraints.EAST;
		gbc_lblPidmask.insets = new Insets(0, 0, 5, 5);
		gbc_lblPidmask.gridx = 0;
		gbc_lblPidmask.gridy = 6;
		panel_7.add(lblPidmask, gbc_lblPidmask);
		
		textField_42 = new JTextField();
		GridBagConstraints gbc_textField_42 = new GridBagConstraints();
		gbc_textField_42.insets = new Insets(0, 0, 5, 5);
		gbc_textField_42.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_42.gridx = 1;
		gbc_textField_42.gridy = 6;
		panel_7.add(textField_42, gbc_textField_42);
		textField_42.setColumns(10);
		
		JLabel lblReserved_1 = new JLabel("Reserved2");
		GridBagConstraints gbc_lblReserved_1 = new GridBagConstraints();
		gbc_lblReserved_1.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved_1.gridx = 2;
		gbc_lblReserved_1.gridy = 6;
		panel_7.add(lblReserved_1, gbc_lblReserved_1);
		
		textField_57 = new JTextField();
		GridBagConstraints gbc_textField_57 = new GridBagConstraints();
		gbc_textField_57.insets = new Insets(0, 0, 5, 0);
		gbc_textField_57.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_57.gridx = 3;
		gbc_textField_57.gridy = 6;
		panel_7.add(textField_57, gbc_textField_57);
		textField_57.setColumns(10);
		
		JLabel lblDcic = new JLabel("DCIC");
		GridBagConstraints gbc_lblDcic = new GridBagConstraints();
		gbc_lblDcic.anchor = GridBagConstraints.EAST;
		gbc_lblDcic.insets = new Insets(0, 0, 5, 5);
		gbc_lblDcic.gridx = 0;
		gbc_lblDcic.gridy = 7;
		panel_7.add(lblDcic, gbc_lblDcic);
		
		textField_43 = new JTextField();
		GridBagConstraints gbc_textField_43 = new GridBagConstraints();
		gbc_textField_43.insets = new Insets(0, 0, 5, 5);
		gbc_textField_43.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_43.gridx = 1;
		gbc_textField_43.gridy = 7;
		panel_7.add(textField_43, gbc_textField_43);
		textField_43.setColumns(10);
		
		JLabel lblReserved_4 = new JLabel("Reserved3");
		GridBagConstraints gbc_lblReserved_4 = new GridBagConstraints();
		gbc_lblReserved_4.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_4.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved_4.gridx = 2;
		gbc_lblReserved_4.gridy = 7;
		panel_7.add(lblReserved_4, gbc_lblReserved_4);
		
		textField_58 = new JTextField();
		GridBagConstraints gbc_textField_58 = new GridBagConstraints();
		gbc_textField_58.insets = new Insets(0, 0, 5, 0);
		gbc_textField_58.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_58.gridx = 3;
		gbc_textField_58.gridy = 7;
		panel_7.add(textField_58, gbc_textField_58);
		textField_58.setColumns(10);
		
		JLabel lblBadvaddr = new JLabel("BadVAddr");
		GridBagConstraints gbc_lblBadvaddr = new GridBagConstraints();
		gbc_lblBadvaddr.anchor = GridBagConstraints.EAST;
		gbc_lblBadvaddr.insets = new Insets(0, 0, 5, 5);
		gbc_lblBadvaddr.gridx = 0;
		gbc_lblBadvaddr.gridy = 8;
		panel_7.add(lblBadvaddr, gbc_lblBadvaddr);
		
		textField_44 = new JTextField();
		GridBagConstraints gbc_textField_44 = new GridBagConstraints();
		gbc_textField_44.insets = new Insets(0, 0, 5, 5);
		gbc_textField_44.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_44.gridx = 1;
		gbc_textField_44.gridy = 8;
		panel_7.add(textField_44, gbc_textField_44);
		textField_44.setColumns(10);
		
		JLabel lblReserved_2 = new JLabel("Reserved4");
		GridBagConstraints gbc_lblReserved_2 = new GridBagConstraints();
		gbc_lblReserved_2.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved_2.gridx = 2;
		gbc_lblReserved_2.gridy = 8;
		panel_7.add(lblReserved_2, gbc_lblReserved_2);
		
		textField_59 = new JTextField();
		GridBagConstraints gbc_textField_59 = new GridBagConstraints();
		gbc_textField_59.insets = new Insets(0, 0, 5, 0);
		gbc_textField_59.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_59.gridx = 3;
		gbc_textField_59.gridy = 8;
		panel_7.add(textField_59, gbc_textField_59);
		textField_59.setColumns(10);
		
		JLabel lblBdam = new JLabel("BDAM");
		GridBagConstraints gbc_lblBdam = new GridBagConstraints();
		gbc_lblBdam.anchor = GridBagConstraints.EAST;
		gbc_lblBdam.insets = new Insets(0, 0, 5, 5);
		gbc_lblBdam.gridx = 0;
		gbc_lblBdam.gridy = 9;
		panel_7.add(lblBdam, gbc_lblBdam);
		
		textField_45 = new JTextField();
		GridBagConstraints gbc_textField_45 = new GridBagConstraints();
		gbc_textField_45.insets = new Insets(0, 0, 5, 5);
		gbc_textField_45.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_45.gridx = 1;
		gbc_textField_45.gridy = 9;
		panel_7.add(textField_45, gbc_textField_45);
		textField_45.setColumns(10);
		
		JLabel lblReserved_3 = new JLabel("Reserved5");
		GridBagConstraints gbc_lblReserved_3 = new GridBagConstraints();
		gbc_lblReserved_3.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_3.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved_3.gridx = 2;
		gbc_lblReserved_3.gridy = 9;
		panel_7.add(lblReserved_3, gbc_lblReserved_3);
		
		textField_60 = new JTextField();
		GridBagConstraints gbc_textField_60 = new GridBagConstraints();
		gbc_textField_60.insets = new Insets(0, 0, 5, 0);
		gbc_textField_60.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_60.gridx = 3;
		gbc_textField_60.gridy = 9;
		panel_7.add(textField_60, gbc_textField_60);
		textField_60.setColumns(10);
		
		JLabel lblEntryhi = new JLabel("EntryHi");
		GridBagConstraints gbc_lblEntryhi = new GridBagConstraints();
		gbc_lblEntryhi.anchor = GridBagConstraints.EAST;
		gbc_lblEntryhi.insets = new Insets(0, 0, 5, 5);
		gbc_lblEntryhi.gridx = 0;
		gbc_lblEntryhi.gridy = 10;
		panel_7.add(lblEntryhi, gbc_lblEntryhi);
		
		textField_46 = new JTextField();
		GridBagConstraints gbc_textField_46 = new GridBagConstraints();
		gbc_textField_46.insets = new Insets(0, 0, 5, 5);
		gbc_textField_46.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_46.gridx = 1;
		gbc_textField_46.gridy = 10;
		panel_7.add(textField_46, gbc_textField_46);
		textField_46.setColumns(10);
		
		JLabel lblEcc = new JLabel("ECC");
		GridBagConstraints gbc_lblEcc = new GridBagConstraints();
		gbc_lblEcc.anchor = GridBagConstraints.EAST;
		gbc_lblEcc.insets = new Insets(0, 0, 5, 5);
		gbc_lblEcc.gridx = 2;
		gbc_lblEcc.gridy = 10;
		panel_7.add(lblEcc, gbc_lblEcc);
		
		textField_61 = new JTextField();
		GridBagConstraints gbc_textField_61 = new GridBagConstraints();
		gbc_textField_61.insets = new Insets(0, 0, 5, 0);
		gbc_textField_61.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_61.gridx = 3;
		gbc_textField_61.gridy = 10;
		panel_7.add(textField_61, gbc_textField_61);
		textField_61.setColumns(10);
		
		JLabel lblBpcm = new JLabel("BPCM");
		GridBagConstraints gbc_lblBpcm = new GridBagConstraints();
		gbc_lblBpcm.anchor = GridBagConstraints.EAST;
		gbc_lblBpcm.insets = new Insets(0, 0, 5, 5);
		gbc_lblBpcm.gridx = 0;
		gbc_lblBpcm.gridy = 11;
		panel_7.add(lblBpcm, gbc_lblBpcm);
		
		textField_47 = new JTextField();
		GridBagConstraints gbc_textField_47 = new GridBagConstraints();
		gbc_textField_47.insets = new Insets(0, 0, 5, 5);
		gbc_textField_47.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_47.gridx = 1;
		gbc_textField_47.gridy = 11;
		panel_7.add(textField_47, gbc_textField_47);
		textField_47.setColumns(10);
		
		JLabel lblCacheerr = new JLabel("CacheErr");
		GridBagConstraints gbc_lblCacheerr = new GridBagConstraints();
		gbc_lblCacheerr.anchor = GridBagConstraints.EAST;
		gbc_lblCacheerr.insets = new Insets(0, 0, 5, 5);
		gbc_lblCacheerr.gridx = 2;
		gbc_lblCacheerr.gridy = 11;
		panel_7.add(lblCacheerr, gbc_lblCacheerr);
		
		textField_62 = new JTextField();
		GridBagConstraints gbc_textField_62 = new GridBagConstraints();
		gbc_textField_62.insets = new Insets(0, 0, 5, 0);
		gbc_textField_62.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_62.gridx = 3;
		gbc_textField_62.gridy = 11;
		panel_7.add(textField_62, gbc_textField_62);
		textField_62.setColumns(10);
		
		JLabel lblStatus = new JLabel("Status");
		GridBagConstraints gbc_lblStatus = new GridBagConstraints();
		gbc_lblStatus.anchor = GridBagConstraints.EAST;
		gbc_lblStatus.insets = new Insets(0, 0, 5, 5);
		gbc_lblStatus.gridx = 0;
		gbc_lblStatus.gridy = 12;
		panel_7.add(lblStatus, gbc_lblStatus);
		
		textField_48 = new JTextField();
		GridBagConstraints gbc_textField_48 = new GridBagConstraints();
		gbc_textField_48.insets = new Insets(0, 0, 5, 5);
		gbc_textField_48.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_48.gridx = 1;
		gbc_textField_48.gridy = 12;
		panel_7.add(textField_48, gbc_textField_48);
		textField_48.setColumns(10);
		
		JLabel lblTaglo = new JLabel("TagLo");
		GridBagConstraints gbc_lblTaglo = new GridBagConstraints();
		gbc_lblTaglo.anchor = GridBagConstraints.EAST;
		gbc_lblTaglo.insets = new Insets(0, 0, 5, 5);
		gbc_lblTaglo.gridx = 2;
		gbc_lblTaglo.gridy = 12;
		panel_7.add(lblTaglo, gbc_lblTaglo);
		
		textField_63 = new JTextField();
		GridBagConstraints gbc_textField_63 = new GridBagConstraints();
		gbc_textField_63.insets = new Insets(0, 0, 5, 0);
		gbc_textField_63.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_63.gridx = 3;
		gbc_textField_63.gridy = 12;
		panel_7.add(textField_63, gbc_textField_63);
		textField_63.setColumns(10);
		
		JLabel lblCause = new JLabel("Cause");
		GridBagConstraints gbc_lblCause = new GridBagConstraints();
		gbc_lblCause.anchor = GridBagConstraints.EAST;
		gbc_lblCause.insets = new Insets(0, 0, 5, 5);
		gbc_lblCause.gridx = 0;
		gbc_lblCause.gridy = 13;
		panel_7.add(lblCause, gbc_lblCause);
		
		textField_49 = new JTextField();
		GridBagConstraints gbc_textField_49 = new GridBagConstraints();
		gbc_textField_49.insets = new Insets(0, 0, 5, 5);
		gbc_textField_49.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_49.gridx = 1;
		gbc_textField_49.gridy = 13;
		panel_7.add(textField_49, gbc_textField_49);
		textField_49.setColumns(10);
		
		JLabel lblTaghi = new JLabel("TagHi");
		GridBagConstraints gbc_lblTaghi = new GridBagConstraints();
		gbc_lblTaghi.anchor = GridBagConstraints.EAST;
		gbc_lblTaghi.insets = new Insets(0, 0, 5, 5);
		gbc_lblTaghi.gridx = 2;
		gbc_lblTaghi.gridy = 13;
		panel_7.add(lblTaghi, gbc_lblTaghi);
		
		textField_64 = new JTextField();
		GridBagConstraints gbc_textField_64 = new GridBagConstraints();
		gbc_textField_64.insets = new Insets(0, 0, 5, 0);
		gbc_textField_64.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_64.gridx = 3;
		gbc_textField_64.gridy = 13;
		panel_7.add(textField_64, gbc_textField_64);
		textField_64.setColumns(10);
		
		JLabel lblEpc = new JLabel("EPC");
		GridBagConstraints gbc_lblEpc = new GridBagConstraints();
		gbc_lblEpc.anchor = GridBagConstraints.EAST;
		gbc_lblEpc.insets = new Insets(0, 0, 5, 5);
		gbc_lblEpc.gridx = 0;
		gbc_lblEpc.gridy = 14;
		panel_7.add(lblEpc, gbc_lblEpc);
		
		textField_50 = new JTextField();
		GridBagConstraints gbc_textField_50 = new GridBagConstraints();
		gbc_textField_50.insets = new Insets(0, 0, 5, 5);
		gbc_textField_50.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_50.gridx = 1;
		gbc_textField_50.gridy = 14;
		panel_7.add(textField_50, gbc_textField_50);
		textField_50.setColumns(10);
		
		JLabel lblErrorepc = new JLabel("ErrorEPC");
		GridBagConstraints gbc_lblErrorepc = new GridBagConstraints();
		gbc_lblErrorepc.anchor = GridBagConstraints.EAST;
		gbc_lblErrorepc.insets = new Insets(0, 0, 5, 5);
		gbc_lblErrorepc.gridx = 2;
		gbc_lblErrorepc.gridy = 14;
		panel_7.add(lblErrorepc, gbc_lblErrorepc);
		
		textField_65 = new JTextField();
		GridBagConstraints gbc_textField_65 = new GridBagConstraints();
		gbc_textField_65.insets = new Insets(0, 0, 5, 0);
		gbc_textField_65.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_65.gridx = 3;
		gbc_textField_65.gridy = 14;
		panel_7.add(textField_65, gbc_textField_65);
		textField_65.setColumns(10);
		
		JLabel lblPrid = new JLabel("PRid");
		GridBagConstraints gbc_lblPrid = new GridBagConstraints();
		gbc_lblPrid.anchor = GridBagConstraints.EAST;
		gbc_lblPrid.insets = new Insets(0, 0, 0, 5);
		gbc_lblPrid.gridx = 0;
		gbc_lblPrid.gridy = 15;
		panel_7.add(lblPrid, gbc_lblPrid);
		
		textField_51 = new JTextField();
		GridBagConstraints gbc_textField_51 = new GridBagConstraints();
		gbc_textField_51.insets = new Insets(0, 0, 0, 5);
		gbc_textField_51.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_51.gridx = 1;
		gbc_textField_51.gridy = 15;
		panel_7.add(textField_51, gbc_textField_51);
		textField_51.setColumns(10);
		
		JLabel lblReserved_5 = new JLabel("Reserved6");
		GridBagConstraints gbc_lblReserved_5 = new GridBagConstraints();
		gbc_lblReserved_5.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_5.insets = new Insets(0, 0, 0, 5);
		gbc_lblReserved_5.gridx = 2;
		gbc_lblReserved_5.gridy = 15;
		panel_7.add(lblReserved_5, gbc_lblReserved_5);
		
		textField_66 = new JTextField();
		GridBagConstraints gbc_textField_66 = new GridBagConstraints();
		gbc_textField_66.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_66.gridx = 3;
		gbc_textField_66.gridy = 15;
		panel_7.add(textField_66, gbc_textField_66);
		textField_66.setColumns(10);
		
		JPanel panel_2 = new JPanel();
		tabbedPane.addTab("COP2 Data", null, panel_2, null);
		GridBagLayout gbl_panel_2 = new GridBagLayout();
		gbl_panel_2.columnWidths = new int[]{217, 0};
		gbl_panel_2.rowHeights = new int[]{464, 0};
		gbl_panel_2.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_2.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		panel_2.setLayout(gbl_panel_2);
		
		JPanel panel_6 = new JPanel();
		GridBagConstraints gbc_panel_6 = new GridBagConstraints();
		gbc_panel_6.fill = GridBagConstraints.BOTH;
		gbc_panel_6.gridx = 0;
		gbc_panel_6.gridy = 0;
		panel_2.add(panel_6, gbc_panel_6);
		GridBagLayout gbl_panel_6 = new GridBagLayout();
		gbl_panel_6.columnWidths = new int[]{41, 0, 0, 0, 22, 0, 0, 0, 0, 0};
		gbl_panel_6.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panel_6.columnWeights = new double[]{0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 1.0, 1.0, 1.0, Double.MIN_VALUE};
		gbl_panel_6.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_6.setLayout(gbl_panel_6);
		
		JLabel lblV = new JLabel("v0");
		GridBagConstraints gbc_lblV = new GridBagConstraints();
		gbc_lblV.insets = new Insets(0, 0, 5, 5);
		gbc_lblV.anchor = GridBagConstraints.EAST;
		gbc_lblV.gridx = 0;
		gbc_lblV.gridy = 0;
		panel_6.add(lblV, gbc_lblV);
		
		textField_67 = new JTextField();
		GridBagConstraints gbc_textField_67 = new GridBagConstraints();
		gbc_textField_67.insets = new Insets(0, 0, 5, 5);
		gbc_textField_67.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_67.gridx = 1;
		gbc_textField_67.gridy = 0;
		panel_6.add(textField_67, gbc_textField_67);
		textField_67.setColumns(10);
		
		textField_68 = new JTextField();
		GridBagConstraints gbc_textField_68 = new GridBagConstraints();
		gbc_textField_68.insets = new Insets(0, 0, 5, 5);
		gbc_textField_68.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_68.gridx = 2;
		gbc_textField_68.gridy = 0;
		panel_6.add(textField_68, gbc_textField_68);
		textField_68.setColumns(10);
		
		textField_69 = new JTextField();
		GridBagConstraints gbc_textField_69 = new GridBagConstraints();
		gbc_textField_69.insets = new Insets(0, 0, 5, 5);
		gbc_textField_69.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_69.gridx = 3;
		gbc_textField_69.gridy = 0;
		panel_6.add(textField_69, gbc_textField_69);
		textField_69.setColumns(10);
		
		JSeparator separator_8 = new JSeparator();
		separator_8.setOrientation(SwingConstants.VERTICAL);
		GridBagConstraints gbc_separator_8 = new GridBagConstraints();
		gbc_separator_8.fill = GridBagConstraints.VERTICAL;
		gbc_separator_8.gridheight = 17;
		gbc_separator_8.insets = new Insets(0, 0, 5, 5);
		gbc_separator_8.gridx = 4;
		gbc_separator_8.gridy = 0;
		panel_6.add(separator_8, gbc_separator_8);
		
		JLabel lblRgb_1 = new JLabel("rgb0");
		GridBagConstraints gbc_lblRgb_1 = new GridBagConstraints();
		gbc_lblRgb_1.anchor = GridBagConstraints.EAST;
		gbc_lblRgb_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblRgb_1.gridx = 5;
		gbc_lblRgb_1.gridy = 0;
		panel_6.add(lblRgb_1, gbc_lblRgb_1);
		
		textField_90 = new JTextField();
		GridBagConstraints gbc_textField_90 = new GridBagConstraints();
		gbc_textField_90.insets = new Insets(0, 0, 5, 5);
		gbc_textField_90.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_90.gridx = 6;
		gbc_textField_90.gridy = 0;
		panel_6.add(textField_90, gbc_textField_90);
		textField_90.setColumns(10);
		
		textField_91 = new JTextField();
		GridBagConstraints gbc_textField_91 = new GridBagConstraints();
		gbc_textField_91.insets = new Insets(0, 0, 5, 5);
		gbc_textField_91.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_91.gridx = 7;
		gbc_textField_91.gridy = 0;
		panel_6.add(textField_91, gbc_textField_91);
		textField_91.setColumns(10);
		
		textField_92 = new JTextField();
		GridBagConstraints gbc_textField_92 = new GridBagConstraints();
		gbc_textField_92.insets = new Insets(0, 0, 5, 0);
		gbc_textField_92.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_92.gridx = 8;
		gbc_textField_92.gridy = 0;
		panel_6.add(textField_92, gbc_textField_92);
		textField_92.setColumns(10);
		
		JLabel lblV_1 = new JLabel("v1");
		GridBagConstraints gbc_lblV_1 = new GridBagConstraints();
		gbc_lblV_1.anchor = GridBagConstraints.EAST;
		gbc_lblV_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblV_1.gridx = 0;
		gbc_lblV_1.gridy = 1;
		panel_6.add(lblV_1, gbc_lblV_1);
		
		textField_70 = new JTextField();
		GridBagConstraints gbc_textField_70 = new GridBagConstraints();
		gbc_textField_70.insets = new Insets(0, 0, 5, 5);
		gbc_textField_70.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_70.gridx = 1;
		gbc_textField_70.gridy = 1;
		panel_6.add(textField_70, gbc_textField_70);
		textField_70.setColumns(10);
		
		textField_71 = new JTextField();
		GridBagConstraints gbc_textField_71 = new GridBagConstraints();
		gbc_textField_71.insets = new Insets(0, 0, 5, 5);
		gbc_textField_71.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_71.gridx = 2;
		gbc_textField_71.gridy = 1;
		panel_6.add(textField_71, gbc_textField_71);
		textField_71.setColumns(10);
		
		textField_72 = new JTextField();
		GridBagConstraints gbc_textField_72 = new GridBagConstraints();
		gbc_textField_72.insets = new Insets(0, 0, 5, 5);
		gbc_textField_72.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_72.gridx = 3;
		gbc_textField_72.gridy = 1;
		panel_6.add(textField_72, gbc_textField_72);
		textField_72.setColumns(10);
		
		JLabel lblRgb_2 = new JLabel("rgb1");
		GridBagConstraints gbc_lblRgb_2 = new GridBagConstraints();
		gbc_lblRgb_2.anchor = GridBagConstraints.EAST;
		gbc_lblRgb_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblRgb_2.gridx = 5;
		gbc_lblRgb_2.gridy = 1;
		panel_6.add(lblRgb_2, gbc_lblRgb_2);
		
		textField_93 = new JTextField();
		GridBagConstraints gbc_textField_93 = new GridBagConstraints();
		gbc_textField_93.insets = new Insets(0, 0, 5, 5);
		gbc_textField_93.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_93.gridx = 6;
		gbc_textField_93.gridy = 1;
		panel_6.add(textField_93, gbc_textField_93);
		textField_93.setColumns(10);
		
		textField_94 = new JTextField();
		GridBagConstraints gbc_textField_94 = new GridBagConstraints();
		gbc_textField_94.insets = new Insets(0, 0, 5, 5);
		gbc_textField_94.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_94.gridx = 7;
		gbc_textField_94.gridy = 1;
		panel_6.add(textField_94, gbc_textField_94);
		textField_94.setColumns(10);
		
		textField_95 = new JTextField();
		GridBagConstraints gbc_textField_95 = new GridBagConstraints();
		gbc_textField_95.insets = new Insets(0, 0, 5, 0);
		gbc_textField_95.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_95.gridx = 8;
		gbc_textField_95.gridy = 1;
		panel_6.add(textField_95, gbc_textField_95);
		textField_95.setColumns(10);
		
		JLabel lblV_2 = new JLabel("v2");
		GridBagConstraints gbc_lblV_2 = new GridBagConstraints();
		gbc_lblV_2.anchor = GridBagConstraints.EAST;
		gbc_lblV_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblV_2.gridx = 0;
		gbc_lblV_2.gridy = 2;
		panel_6.add(lblV_2, gbc_lblV_2);
		
		textField_73 = new JTextField();
		GridBagConstraints gbc_textField_73 = new GridBagConstraints();
		gbc_textField_73.insets = new Insets(0, 0, 5, 5);
		gbc_textField_73.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_73.gridx = 1;
		gbc_textField_73.gridy = 2;
		panel_6.add(textField_73, gbc_textField_73);
		textField_73.setColumns(10);
		
		textField_74 = new JTextField();
		GridBagConstraints gbc_textField_74 = new GridBagConstraints();
		gbc_textField_74.insets = new Insets(0, 0, 5, 5);
		gbc_textField_74.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_74.gridx = 2;
		gbc_textField_74.gridy = 2;
		panel_6.add(textField_74, gbc_textField_74);
		textField_74.setColumns(10);
		
		textField_75 = new JTextField();
		GridBagConstraints gbc_textField_75 = new GridBagConstraints();
		gbc_textField_75.insets = new Insets(0, 0, 5, 5);
		gbc_textField_75.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_75.gridx = 3;
		gbc_textField_75.gridy = 2;
		panel_6.add(textField_75, gbc_textField_75);
		textField_75.setColumns(10);
		
		JLabel lblRgb_3 = new JLabel("rgb2");
		GridBagConstraints gbc_lblRgb_3 = new GridBagConstraints();
		gbc_lblRgb_3.anchor = GridBagConstraints.EAST;
		gbc_lblRgb_3.insets = new Insets(0, 0, 5, 5);
		gbc_lblRgb_3.gridx = 5;
		gbc_lblRgb_3.gridy = 2;
		panel_6.add(lblRgb_3, gbc_lblRgb_3);
		
		textField_96 = new JTextField();
		GridBagConstraints gbc_textField_96 = new GridBagConstraints();
		gbc_textField_96.insets = new Insets(0, 0, 5, 5);
		gbc_textField_96.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_96.gridx = 6;
		gbc_textField_96.gridy = 2;
		panel_6.add(textField_96, gbc_textField_96);
		textField_96.setColumns(10);
		
		textField_97 = new JTextField();
		GridBagConstraints gbc_textField_97 = new GridBagConstraints();
		gbc_textField_97.insets = new Insets(0, 0, 5, 5);
		gbc_textField_97.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_97.gridx = 7;
		gbc_textField_97.gridy = 2;
		panel_6.add(textField_97, gbc_textField_97);
		textField_97.setColumns(10);
		
		textField_98 = new JTextField();
		GridBagConstraints gbc_textField_98 = new GridBagConstraints();
		gbc_textField_98.insets = new Insets(0, 0, 5, 0);
		gbc_textField_98.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_98.gridx = 8;
		gbc_textField_98.gridy = 2;
		panel_6.add(textField_98, gbc_textField_98);
		textField_98.setColumns(10);
		
		JLabel lblRgb = new JLabel("rgb");
		GridBagConstraints gbc_lblRgb = new GridBagConstraints();
		gbc_lblRgb.anchor = GridBagConstraints.EAST;
		gbc_lblRgb.insets = new Insets(0, 0, 5, 5);
		gbc_lblRgb.gridx = 0;
		gbc_lblRgb.gridy = 3;
		panel_6.add(lblRgb, gbc_lblRgb);
		
		textField_76 = new JTextField();
		GridBagConstraints gbc_textField_76 = new GridBagConstraints();
		gbc_textField_76.insets = new Insets(0, 0, 5, 5);
		gbc_textField_76.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_76.gridx = 1;
		gbc_textField_76.gridy = 3;
		panel_6.add(textField_76, gbc_textField_76);
		textField_76.setColumns(10);
		
		JLabel lblReserved_6 = new JLabel("reserved");
		GridBagConstraints gbc_lblReserved_6 = new GridBagConstraints();
		gbc_lblReserved_6.anchor = GridBagConstraints.EAST;
		gbc_lblReserved_6.insets = new Insets(0, 0, 5, 5);
		gbc_lblReserved_6.gridx = 5;
		gbc_lblReserved_6.gridy = 3;
		panel_6.add(lblReserved_6, gbc_lblReserved_6);
		
		textField_99 = new JTextField();
		GridBagConstraints gbc_textField_99 = new GridBagConstraints();
		gbc_textField_99.insets = new Insets(0, 0, 5, 5);
		gbc_textField_99.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_99.gridx = 6;
		gbc_textField_99.gridy = 3;
		panel_6.add(textField_99, gbc_textField_99);
		textField_99.setColumns(10);
		
		JLabel lblOtz = new JLabel("otz");
		GridBagConstraints gbc_lblOtz = new GridBagConstraints();
		gbc_lblOtz.anchor = GridBagConstraints.EAST;
		gbc_lblOtz.insets = new Insets(0, 0, 5, 5);
		gbc_lblOtz.gridx = 0;
		gbc_lblOtz.gridy = 4;
		panel_6.add(lblOtz, gbc_lblOtz);
		
		textField_77 = new JTextField();
		GridBagConstraints gbc_textField_77 = new GridBagConstraints();
		gbc_textField_77.insets = new Insets(0, 0, 5, 5);
		gbc_textField_77.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_77.gridx = 1;
		gbc_textField_77.gridy = 4;
		panel_6.add(textField_77, gbc_textField_77);
		textField_77.setColumns(10);
		
		JLabel lblMac = new JLabel("mac0");
		GridBagConstraints gbc_lblMac = new GridBagConstraints();
		gbc_lblMac.anchor = GridBagConstraints.EAST;
		gbc_lblMac.insets = new Insets(0, 0, 5, 5);
		gbc_lblMac.gridx = 5;
		gbc_lblMac.gridy = 4;
		panel_6.add(lblMac, gbc_lblMac);
		
		textField_100 = new JTextField();
		GridBagConstraints gbc_textField_100 = new GridBagConstraints();
		gbc_textField_100.insets = new Insets(0, 0, 5, 5);
		gbc_textField_100.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_100.gridx = 6;
		gbc_textField_100.gridy = 4;
		panel_6.add(textField_100, gbc_textField_100);
		textField_100.setColumns(10);
		
		JLabel lblIr = new JLabel("ir0");
		GridBagConstraints gbc_lblIr = new GridBagConstraints();
		gbc_lblIr.anchor = GridBagConstraints.EAST;
		gbc_lblIr.insets = new Insets(0, 0, 5, 5);
		gbc_lblIr.gridx = 0;
		gbc_lblIr.gridy = 5;
		panel_6.add(lblIr, gbc_lblIr);
		
		textField_78 = new JTextField();
		GridBagConstraints gbc_textField_78 = new GridBagConstraints();
		gbc_textField_78.insets = new Insets(0, 0, 5, 5);
		gbc_textField_78.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_78.gridx = 1;
		gbc_textField_78.gridy = 5;
		panel_6.add(textField_78, gbc_textField_78);
		textField_78.setColumns(10);
		
		JLabel lblMac_1 = new JLabel("mac1");
		GridBagConstraints gbc_lblMac_1 = new GridBagConstraints();
		gbc_lblMac_1.anchor = GridBagConstraints.EAST;
		gbc_lblMac_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblMac_1.gridx = 5;
		gbc_lblMac_1.gridy = 5;
		panel_6.add(lblMac_1, gbc_lblMac_1);
		
		textField_101 = new JTextField();
		GridBagConstraints gbc_textField_101 = new GridBagConstraints();
		gbc_textField_101.insets = new Insets(0, 0, 5, 5);
		gbc_textField_101.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_101.gridx = 6;
		gbc_textField_101.gridy = 5;
		panel_6.add(textField_101, gbc_textField_101);
		textField_101.setColumns(10);
		
		JLabel lblIr_1 = new JLabel("ir1");
		GridBagConstraints gbc_lblIr_1 = new GridBagConstraints();
		gbc_lblIr_1.anchor = GridBagConstraints.EAST;
		gbc_lblIr_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblIr_1.gridx = 0;
		gbc_lblIr_1.gridy = 6;
		panel_6.add(lblIr_1, gbc_lblIr_1);
		
		textField_79 = new JTextField();
		GridBagConstraints gbc_textField_79 = new GridBagConstraints();
		gbc_textField_79.insets = new Insets(0, 0, 5, 5);
		gbc_textField_79.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_79.gridx = 1;
		gbc_textField_79.gridy = 6;
		panel_6.add(textField_79, gbc_textField_79);
		textField_79.setColumns(10);
		
		JLabel lblMac_2 = new JLabel("mac2");
		GridBagConstraints gbc_lblMac_2 = new GridBagConstraints();
		gbc_lblMac_2.anchor = GridBagConstraints.EAST;
		gbc_lblMac_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblMac_2.gridx = 5;
		gbc_lblMac_2.gridy = 6;
		panel_6.add(lblMac_2, gbc_lblMac_2);
		
		textField_102 = new JTextField();
		GridBagConstraints gbc_textField_102 = new GridBagConstraints();
		gbc_textField_102.insets = new Insets(0, 0, 5, 5);
		gbc_textField_102.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_102.gridx = 6;
		gbc_textField_102.gridy = 6;
		panel_6.add(textField_102, gbc_textField_102);
		textField_102.setColumns(10);
		
		JLabel lblIr_2 = new JLabel("ir2");
		GridBagConstraints gbc_lblIr_2 = new GridBagConstraints();
		gbc_lblIr_2.anchor = GridBagConstraints.EAST;
		gbc_lblIr_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblIr_2.gridx = 0;
		gbc_lblIr_2.gridy = 7;
		panel_6.add(lblIr_2, gbc_lblIr_2);
		
		textField_80 = new JTextField();
		GridBagConstraints gbc_textField_80 = new GridBagConstraints();
		gbc_textField_80.insets = new Insets(0, 0, 5, 5);
		gbc_textField_80.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_80.gridx = 1;
		gbc_textField_80.gridy = 7;
		panel_6.add(textField_80, gbc_textField_80);
		textField_80.setColumns(10);
		
		JLabel lblMac_3 = new JLabel("mac3");
		GridBagConstraints gbc_lblMac_3 = new GridBagConstraints();
		gbc_lblMac_3.anchor = GridBagConstraints.EAST;
		gbc_lblMac_3.insets = new Insets(0, 0, 5, 5);
		gbc_lblMac_3.gridx = 5;
		gbc_lblMac_3.gridy = 7;
		panel_6.add(lblMac_3, gbc_lblMac_3);
		
		textField_103 = new JTextField();
		GridBagConstraints gbc_textField_103 = new GridBagConstraints();
		gbc_textField_103.insets = new Insets(0, 0, 5, 5);
		gbc_textField_103.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_103.gridx = 6;
		gbc_textField_103.gridy = 7;
		panel_6.add(textField_103, gbc_textField_103);
		textField_103.setColumns(10);
		
		JLabel lblIr_3 = new JLabel("ir3");
		GridBagConstraints gbc_lblIr_3 = new GridBagConstraints();
		gbc_lblIr_3.anchor = GridBagConstraints.EAST;
		gbc_lblIr_3.insets = new Insets(0, 0, 5, 5);
		gbc_lblIr_3.gridx = 0;
		gbc_lblIr_3.gridy = 8;
		panel_6.add(lblIr_3, gbc_lblIr_3);
		
		textField_81 = new JTextField();
		GridBagConstraints gbc_textField_81 = new GridBagConstraints();
		gbc_textField_81.insets = new Insets(0, 0, 5, 5);
		gbc_textField_81.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_81.gridx = 1;
		gbc_textField_81.gridy = 8;
		panel_6.add(textField_81, gbc_textField_81);
		textField_81.setColumns(10);
		
		JLabel lblIrgb = new JLabel("irgb");
		GridBagConstraints gbc_lblIrgb = new GridBagConstraints();
		gbc_lblIrgb.anchor = GridBagConstraints.EAST;
		gbc_lblIrgb.insets = new Insets(0, 0, 5, 5);
		gbc_lblIrgb.gridx = 5;
		gbc_lblIrgb.gridy = 8;
		panel_6.add(lblIrgb, gbc_lblIrgb);
		
		textField_104 = new JTextField();
		GridBagConstraints gbc_textField_104 = new GridBagConstraints();
		gbc_textField_104.insets = new Insets(0, 0, 5, 5);
		gbc_textField_104.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_104.gridx = 6;
		gbc_textField_104.gridy = 8;
		panel_6.add(textField_104, gbc_textField_104);
		textField_104.setColumns(10);
		
		JLabel lblSxy = new JLabel("sxy0");
		GridBagConstraints gbc_lblSxy = new GridBagConstraints();
		gbc_lblSxy.anchor = GridBagConstraints.EAST;
		gbc_lblSxy.insets = new Insets(0, 0, 5, 5);
		gbc_lblSxy.gridx = 0;
		gbc_lblSxy.gridy = 9;
		panel_6.add(lblSxy, gbc_lblSxy);
		
		textField_82 = new JTextField();
		GridBagConstraints gbc_textField_82 = new GridBagConstraints();
		gbc_textField_82.insets = new Insets(0, 0, 5, 5);
		gbc_textField_82.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_82.gridx = 1;
		gbc_textField_82.gridy = 9;
		panel_6.add(textField_82, gbc_textField_82);
		textField_82.setColumns(10);
		
		JLabel lblOrgb = new JLabel("orgb");
		GridBagConstraints gbc_lblOrgb = new GridBagConstraints();
		gbc_lblOrgb.anchor = GridBagConstraints.EAST;
		gbc_lblOrgb.insets = new Insets(0, 0, 5, 5);
		gbc_lblOrgb.gridx = 5;
		gbc_lblOrgb.gridy = 9;
		panel_6.add(lblOrgb, gbc_lblOrgb);
		
		textField_105 = new JTextField();
		GridBagConstraints gbc_textField_105 = new GridBagConstraints();
		gbc_textField_105.insets = new Insets(0, 0, 5, 5);
		gbc_textField_105.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_105.gridx = 6;
		gbc_textField_105.gridy = 9;
		panel_6.add(textField_105, gbc_textField_105);
		textField_105.setColumns(10);
		
		JLabel lblSxy_1 = new JLabel("sxy1");
		GridBagConstraints gbc_lblSxy_1 = new GridBagConstraints();
		gbc_lblSxy_1.anchor = GridBagConstraints.EAST;
		gbc_lblSxy_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblSxy_1.gridx = 0;
		gbc_lblSxy_1.gridy = 10;
		panel_6.add(lblSxy_1, gbc_lblSxy_1);
		
		textField_83 = new JTextField();
		GridBagConstraints gbc_textField_83 = new GridBagConstraints();
		gbc_textField_83.insets = new Insets(0, 0, 5, 5);
		gbc_textField_83.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_83.gridx = 1;
		gbc_textField_83.gridy = 10;
		panel_6.add(textField_83, gbc_textField_83);
		textField_83.setColumns(10);
		
		JLabel lblLzcs = new JLabel("lzcs");
		GridBagConstraints gbc_lblLzcs = new GridBagConstraints();
		gbc_lblLzcs.anchor = GridBagConstraints.EAST;
		gbc_lblLzcs.insets = new Insets(0, 0, 5, 5);
		gbc_lblLzcs.gridx = 5;
		gbc_lblLzcs.gridy = 10;
		panel_6.add(lblLzcs, gbc_lblLzcs);
		
		textField_106 = new JTextField();
		GridBagConstraints gbc_textField_106 = new GridBagConstraints();
		gbc_textField_106.insets = new Insets(0, 0, 5, 5);
		gbc_textField_106.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_106.gridx = 6;
		gbc_textField_106.gridy = 10;
		panel_6.add(textField_106, gbc_textField_106);
		textField_106.setColumns(10);
		
		JLabel lblSxy_2 = new JLabel("sxy2");
		GridBagConstraints gbc_lblSxy_2 = new GridBagConstraints();
		gbc_lblSxy_2.anchor = GridBagConstraints.EAST;
		gbc_lblSxy_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblSxy_2.gridx = 0;
		gbc_lblSxy_2.gridy = 11;
		panel_6.add(lblSxy_2, gbc_lblSxy_2);
		
		textField_84 = new JTextField();
		GridBagConstraints gbc_textField_84 = new GridBagConstraints();
		gbc_textField_84.insets = new Insets(0, 0, 5, 5);
		gbc_textField_84.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_84.gridx = 1;
		gbc_textField_84.gridy = 11;
		panel_6.add(textField_84, gbc_textField_84);
		textField_84.setColumns(10);
		
		JLabel lblLzcr = new JLabel("lzcr");
		GridBagConstraints gbc_lblLzcr = new GridBagConstraints();
		gbc_lblLzcr.anchor = GridBagConstraints.EAST;
		gbc_lblLzcr.insets = new Insets(0, 0, 5, 5);
		gbc_lblLzcr.gridx = 5;
		gbc_lblLzcr.gridy = 11;
		panel_6.add(lblLzcr, gbc_lblLzcr);
		
		textField_107 = new JTextField();
		GridBagConstraints gbc_textField_107 = new GridBagConstraints();
		gbc_textField_107.insets = new Insets(0, 0, 5, 5);
		gbc_textField_107.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_107.gridx = 6;
		gbc_textField_107.gridy = 11;
		panel_6.add(textField_107, gbc_textField_107);
		textField_107.setColumns(10);
		
		JLabel lblSxyp = new JLabel("sxyp");
		GridBagConstraints gbc_lblSxyp = new GridBagConstraints();
		gbc_lblSxyp.anchor = GridBagConstraints.EAST;
		gbc_lblSxyp.insets = new Insets(0, 0, 5, 5);
		gbc_lblSxyp.gridx = 0;
		gbc_lblSxyp.gridy = 12;
		panel_6.add(lblSxyp, gbc_lblSxyp);
		
		textField_85 = new JTextField();
		GridBagConstraints gbc_textField_85 = new GridBagConstraints();
		gbc_textField_85.insets = new Insets(0, 0, 5, 5);
		gbc_textField_85.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_85.gridx = 1;
		gbc_textField_85.gridy = 12;
		panel_6.add(textField_85, gbc_textField_85);
		textField_85.setColumns(10);
		
		JLabel lblSz = new JLabel("sz0");
		GridBagConstraints gbc_lblSz = new GridBagConstraints();
		gbc_lblSz.anchor = GridBagConstraints.EAST;
		gbc_lblSz.insets = new Insets(0, 0, 5, 5);
		gbc_lblSz.gridx = 0;
		gbc_lblSz.gridy = 13;
		panel_6.add(lblSz, gbc_lblSz);
		
		textField_86 = new JTextField();
		GridBagConstraints gbc_textField_86 = new GridBagConstraints();
		gbc_textField_86.insets = new Insets(0, 0, 5, 5);
		gbc_textField_86.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_86.gridx = 1;
		gbc_textField_86.gridy = 13;
		panel_6.add(textField_86, gbc_textField_86);
		textField_86.setColumns(10);
		
		JLabel lblSz_1 = new JLabel("sz1");
		GridBagConstraints gbc_lblSz_1 = new GridBagConstraints();
		gbc_lblSz_1.anchor = GridBagConstraints.EAST;
		gbc_lblSz_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblSz_1.gridx = 0;
		gbc_lblSz_1.gridy = 14;
		panel_6.add(lblSz_1, gbc_lblSz_1);
		
		textField_87 = new JTextField();
		GridBagConstraints gbc_textField_87 = new GridBagConstraints();
		gbc_textField_87.insets = new Insets(0, 0, 5, 5);
		gbc_textField_87.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_87.gridx = 1;
		gbc_textField_87.gridy = 14;
		panel_6.add(textField_87, gbc_textField_87);
		textField_87.setColumns(10);
		
		JLabel lblSz_2 = new JLabel("sz2");
		GridBagConstraints gbc_lblSz_2 = new GridBagConstraints();
		gbc_lblSz_2.anchor = GridBagConstraints.EAST;
		gbc_lblSz_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblSz_2.gridx = 0;
		gbc_lblSz_2.gridy = 15;
		panel_6.add(lblSz_2, gbc_lblSz_2);
		
		textField_88 = new JTextField();
		GridBagConstraints gbc_textField_88 = new GridBagConstraints();
		gbc_textField_88.insets = new Insets(0, 0, 5, 5);
		gbc_textField_88.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_88.gridx = 1;
		gbc_textField_88.gridy = 15;
		panel_6.add(textField_88, gbc_textField_88);
		textField_88.setColumns(10);
		
		JLabel lblSz_3 = new JLabel("sz3");
		GridBagConstraints gbc_lblSz_3 = new GridBagConstraints();
		gbc_lblSz_3.anchor = GridBagConstraints.EAST;
		gbc_lblSz_3.insets = new Insets(0, 0, 0, 5);
		gbc_lblSz_3.gridx = 0;
		gbc_lblSz_3.gridy = 16;
		panel_6.add(lblSz_3, gbc_lblSz_3);
		
		textField_89 = new JTextField();
		GridBagConstraints gbc_textField_89 = new GridBagConstraints();
		gbc_textField_89.insets = new Insets(0, 0, 0, 5);
		gbc_textField_89.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_89.gridx = 1;
		gbc_textField_89.gridy = 16;
		panel_6.add(textField_89, gbc_textField_89);
		textField_89.setColumns(10);
		
		JPanel panel_3 = new JPanel();
		tabbedPane.addTab("COP2 Control", null, panel_3, null);
		GridBagLayout gbl_panel_3 = new GridBagLayout();
		gbl_panel_3.columnWidths = new int[]{107, 0};
		gbl_panel_3.rowHeights = new int[]{320, 0};
		gbl_panel_3.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_3.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		panel_3.setLayout(gbl_panel_3);
		
		JPanel panel_8 = new JPanel();
		GridBagConstraints gbc_panel_8 = new GridBagConstraints();
		gbc_panel_8.anchor = GridBagConstraints.NORTHWEST;
		gbc_panel_8.gridx = 0;
		gbc_panel_8.gridy = 0;
		panel_3.add(panel_8, gbc_panel_8);
		GridBagLayout gbl_panel_8 = new GridBagLayout();
		gbl_panel_8.columnWidths = new int[]{57, 0, 0, 0, 0};
		gbl_panel_8.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panel_8.columnWeights = new double[]{0.0, 1.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_8.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_8.setLayout(gbl_panel_8);
		
		JLabel lblRmatrix = new JLabel("rMatrix");
		GridBagConstraints gbc_lblRmatrix = new GridBagConstraints();
		gbc_lblRmatrix.anchor = GridBagConstraints.EAST;
		gbc_lblRmatrix.insets = new Insets(0, 0, 5, 5);
		gbc_lblRmatrix.gridx = 0;
		gbc_lblRmatrix.gridy = 0;
		panel_8.add(lblRmatrix, gbc_lblRmatrix);
		
		textField_108 = new JTextField();
		GridBagConstraints gbc_textField_108 = new GridBagConstraints();
		gbc_textField_108.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_108.insets = new Insets(0, 0, 5, 5);
		gbc_textField_108.gridx = 1;
		gbc_textField_108.gridy = 0;
		panel_8.add(textField_108, gbc_textField_108);
		textField_108.setColumns(10);
		
		JLabel lblOfx = new JLabel("ofx");
		GridBagConstraints gbc_lblOfx = new GridBagConstraints();
		gbc_lblOfx.anchor = GridBagConstraints.EAST;
		gbc_lblOfx.insets = new Insets(0, 0, 5, 5);
		gbc_lblOfx.gridx = 2;
		gbc_lblOfx.gridy = 0;
		panel_8.add(lblOfx, gbc_lblOfx);
		
		textField_118 = new JTextField();
		GridBagConstraints gbc_textField_118 = new GridBagConstraints();
		gbc_textField_118.insets = new Insets(0, 0, 5, 0);
		gbc_textField_118.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_118.gridx = 3;
		gbc_textField_118.gridy = 0;
		panel_8.add(textField_118, gbc_textField_118);
		textField_118.setColumns(10);
		
		JLabel lblTrx = new JLabel("trX");
		GridBagConstraints gbc_lblTrx = new GridBagConstraints();
		gbc_lblTrx.anchor = GridBagConstraints.EAST;
		gbc_lblTrx.insets = new Insets(0, 0, 5, 5);
		gbc_lblTrx.gridx = 0;
		gbc_lblTrx.gridy = 1;
		panel_8.add(lblTrx, gbc_lblTrx);
		
		textField_109 = new JTextField();
		GridBagConstraints gbc_textField_109 = new GridBagConstraints();
		gbc_textField_109.insets = new Insets(0, 0, 5, 5);
		gbc_textField_109.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_109.gridx = 1;
		gbc_textField_109.gridy = 1;
		panel_8.add(textField_109, gbc_textField_109);
		textField_109.setColumns(10);
		
		JLabel lblOfy = new JLabel("ofy");
		GridBagConstraints gbc_lblOfy = new GridBagConstraints();
		gbc_lblOfy.anchor = GridBagConstraints.EAST;
		gbc_lblOfy.insets = new Insets(0, 0, 5, 5);
		gbc_lblOfy.gridx = 2;
		gbc_lblOfy.gridy = 1;
		panel_8.add(lblOfy, gbc_lblOfy);
		
		textField_121 = new JTextField();
		GridBagConstraints gbc_textField_121 = new GridBagConstraints();
		gbc_textField_121.insets = new Insets(0, 0, 5, 0);
		gbc_textField_121.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_121.gridx = 3;
		gbc_textField_121.gridy = 1;
		panel_8.add(textField_121, gbc_textField_121);
		textField_121.setColumns(10);
		
		JLabel lblTry = new JLabel("trY");
		GridBagConstraints gbc_lblTry = new GridBagConstraints();
		gbc_lblTry.anchor = GridBagConstraints.EAST;
		gbc_lblTry.insets = new Insets(0, 0, 5, 5);
		gbc_lblTry.gridx = 0;
		gbc_lblTry.gridy = 2;
		panel_8.add(lblTry, gbc_lblTry);
		
		textField_110 = new JTextField();
		GridBagConstraints gbc_textField_110 = new GridBagConstraints();
		gbc_textField_110.insets = new Insets(0, 0, 5, 5);
		gbc_textField_110.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_110.gridx = 1;
		gbc_textField_110.gridy = 2;
		panel_8.add(textField_110, gbc_textField_110);
		textField_110.setColumns(10);
		
		JLabel lblH = new JLabel("h");
		GridBagConstraints gbc_lblH = new GridBagConstraints();
		gbc_lblH.insets = new Insets(0, 0, 5, 5);
		gbc_lblH.gridx = 2;
		gbc_lblH.gridy = 2;
		panel_8.add(lblH, gbc_lblH);
		
		textField_122 = new JTextField();
		GridBagConstraints gbc_textField_122 = new GridBagConstraints();
		gbc_textField_122.insets = new Insets(0, 0, 5, 0);
		gbc_textField_122.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_122.gridx = 3;
		gbc_textField_122.gridy = 2;
		panel_8.add(textField_122, gbc_textField_122);
		textField_122.setColumns(10);
		
		JLabel lblTrz = new JLabel("trZ");
		GridBagConstraints gbc_lblTrz = new GridBagConstraints();
		gbc_lblTrz.anchor = GridBagConstraints.EAST;
		gbc_lblTrz.insets = new Insets(0, 0, 5, 5);
		gbc_lblTrz.gridx = 0;
		gbc_lblTrz.gridy = 3;
		panel_8.add(lblTrz, gbc_lblTrz);
		
		textField_111 = new JTextField();
		GridBagConstraints gbc_textField_111 = new GridBagConstraints();
		gbc_textField_111.insets = new Insets(0, 0, 5, 5);
		gbc_textField_111.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_111.gridx = 1;
		gbc_textField_111.gridy = 3;
		panel_8.add(textField_111, gbc_textField_111);
		textField_111.setColumns(10);
		
		JLabel lblDqa = new JLabel("dqa");
		GridBagConstraints gbc_lblDqa = new GridBagConstraints();
		gbc_lblDqa.anchor = GridBagConstraints.EAST;
		gbc_lblDqa.insets = new Insets(0, 0, 5, 5);
		gbc_lblDqa.gridx = 2;
		gbc_lblDqa.gridy = 3;
		panel_8.add(lblDqa, gbc_lblDqa);
		
		textField_123 = new JTextField();
		GridBagConstraints gbc_textField_123 = new GridBagConstraints();
		gbc_textField_123.insets = new Insets(0, 0, 5, 0);
		gbc_textField_123.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_123.gridx = 3;
		gbc_textField_123.gridy = 3;
		panel_8.add(textField_123, gbc_textField_123);
		textField_123.setColumns(10);
		
		JLabel lblLmatrix = new JLabel("lMatrix");
		GridBagConstraints gbc_lblLmatrix = new GridBagConstraints();
		gbc_lblLmatrix.anchor = GridBagConstraints.EAST;
		gbc_lblLmatrix.insets = new Insets(0, 0, 5, 5);
		gbc_lblLmatrix.gridx = 0;
		gbc_lblLmatrix.gridy = 4;
		panel_8.add(lblLmatrix, gbc_lblLmatrix);
		
		textField_112 = new JTextField();
		GridBagConstraints gbc_textField_112 = new GridBagConstraints();
		gbc_textField_112.insets = new Insets(0, 0, 5, 5);
		gbc_textField_112.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_112.gridx = 1;
		gbc_textField_112.gridy = 4;
		panel_8.add(textField_112, gbc_textField_112);
		textField_112.setColumns(10);
		
		JLabel lblDqb = new JLabel("dqb");
		GridBagConstraints gbc_lblDqb = new GridBagConstraints();
		gbc_lblDqb.anchor = GridBagConstraints.EAST;
		gbc_lblDqb.insets = new Insets(0, 0, 5, 5);
		gbc_lblDqb.gridx = 2;
		gbc_lblDqb.gridy = 4;
		panel_8.add(lblDqb, gbc_lblDqb);
		
		textField_124 = new JTextField();
		GridBagConstraints gbc_textField_124 = new GridBagConstraints();
		gbc_textField_124.insets = new Insets(0, 0, 5, 0);
		gbc_textField_124.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_124.gridx = 3;
		gbc_textField_124.gridy = 4;
		panel_8.add(textField_124, gbc_textField_124);
		textField_124.setColumns(10);
		
		JLabel lblRbk = new JLabel("rbk");
		GridBagConstraints gbc_lblRbk = new GridBagConstraints();
		gbc_lblRbk.anchor = GridBagConstraints.EAST;
		gbc_lblRbk.insets = new Insets(0, 0, 5, 5);
		gbc_lblRbk.gridx = 0;
		gbc_lblRbk.gridy = 5;
		panel_8.add(lblRbk, gbc_lblRbk);
		
		textField_113 = new JTextField();
		GridBagConstraints gbc_textField_113 = new GridBagConstraints();
		gbc_textField_113.insets = new Insets(0, 0, 5, 5);
		gbc_textField_113.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_113.gridx = 1;
		gbc_textField_113.gridy = 5;
		panel_8.add(textField_113, gbc_textField_113);
		textField_113.setColumns(10);
		
		JLabel lblZsf = new JLabel("zsf3");
		GridBagConstraints gbc_lblZsf = new GridBagConstraints();
		gbc_lblZsf.anchor = GridBagConstraints.EAST;
		gbc_lblZsf.insets = new Insets(0, 0, 5, 5);
		gbc_lblZsf.gridx = 2;
		gbc_lblZsf.gridy = 5;
		panel_8.add(lblZsf, gbc_lblZsf);
		
		textField_125 = new JTextField();
		GridBagConstraints gbc_textField_125 = new GridBagConstraints();
		gbc_textField_125.insets = new Insets(0, 0, 5, 0);
		gbc_textField_125.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_125.gridx = 3;
		gbc_textField_125.gridy = 5;
		panel_8.add(textField_125, gbc_textField_125);
		textField_125.setColumns(10);
		
		JLabel lblGbk = new JLabel("gbk");
		GridBagConstraints gbc_lblGbk = new GridBagConstraints();
		gbc_lblGbk.anchor = GridBagConstraints.EAST;
		gbc_lblGbk.insets = new Insets(0, 0, 5, 5);
		gbc_lblGbk.gridx = 0;
		gbc_lblGbk.gridy = 6;
		panel_8.add(lblGbk, gbc_lblGbk);
		
		textField_114 = new JTextField();
		GridBagConstraints gbc_textField_114 = new GridBagConstraints();
		gbc_textField_114.insets = new Insets(0, 0, 5, 5);
		gbc_textField_114.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_114.gridx = 1;
		gbc_textField_114.gridy = 6;
		panel_8.add(textField_114, gbc_textField_114);
		textField_114.setColumns(10);
		
		JLabel lblZsf_1 = new JLabel("zsf4");
		GridBagConstraints gbc_lblZsf_1 = new GridBagConstraints();
		gbc_lblZsf_1.anchor = GridBagConstraints.EAST;
		gbc_lblZsf_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblZsf_1.gridx = 2;
		gbc_lblZsf_1.gridy = 6;
		panel_8.add(lblZsf_1, gbc_lblZsf_1);
		
		textField_126 = new JTextField();
		GridBagConstraints gbc_textField_126 = new GridBagConstraints();
		gbc_textField_126.insets = new Insets(0, 0, 5, 0);
		gbc_textField_126.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_126.gridx = 3;
		gbc_textField_126.gridy = 6;
		panel_8.add(textField_126, gbc_textField_126);
		textField_126.setColumns(10);
		
		JLabel lblBbk = new JLabel("bbk");
		GridBagConstraints gbc_lblBbk = new GridBagConstraints();
		gbc_lblBbk.anchor = GridBagConstraints.EAST;
		gbc_lblBbk.insets = new Insets(0, 0, 5, 5);
		gbc_lblBbk.gridx = 0;
		gbc_lblBbk.gridy = 7;
		panel_8.add(lblBbk, gbc_lblBbk);
		
		textField_115 = new JTextField();
		GridBagConstraints gbc_textField_115 = new GridBagConstraints();
		gbc_textField_115.insets = new Insets(0, 0, 5, 5);
		gbc_textField_115.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_115.gridx = 1;
		gbc_textField_115.gridy = 7;
		panel_8.add(textField_115, gbc_textField_115);
		textField_115.setColumns(10);
		
		JLabel lblFlag = new JLabel("flag");
		GridBagConstraints gbc_lblFlag = new GridBagConstraints();
		gbc_lblFlag.anchor = GridBagConstraints.EAST;
		gbc_lblFlag.insets = new Insets(0, 0, 5, 5);
		gbc_lblFlag.gridx = 2;
		gbc_lblFlag.gridy = 7;
		panel_8.add(lblFlag, gbc_lblFlag);
		
		textField_127 = new JTextField();
		GridBagConstraints gbc_textField_127 = new GridBagConstraints();
		gbc_textField_127.insets = new Insets(0, 0, 5, 0);
		gbc_textField_127.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_127.gridx = 3;
		gbc_textField_127.gridy = 7;
		panel_8.add(textField_127, gbc_textField_127);
		textField_127.setColumns(10);
		
		JLabel lblCmatrix = new JLabel("cMatrix");
		GridBagConstraints gbc_lblCmatrix = new GridBagConstraints();
		gbc_lblCmatrix.anchor = GridBagConstraints.EAST;
		gbc_lblCmatrix.insets = new Insets(0, 0, 5, 5);
		gbc_lblCmatrix.gridx = 0;
		gbc_lblCmatrix.gridy = 8;
		panel_8.add(lblCmatrix, gbc_lblCmatrix);
		
		textField_116 = new JTextField();
		GridBagConstraints gbc_textField_116 = new GridBagConstraints();
		gbc_textField_116.insets = new Insets(0, 0, 5, 5);
		gbc_textField_116.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_116.gridx = 1;
		gbc_textField_116.gridy = 8;
		panel_8.add(textField_116, gbc_textField_116);
		textField_116.setColumns(10);
		
		JLabel lblRfc = new JLabel("rfc");
		GridBagConstraints gbc_lblRfc = new GridBagConstraints();
		gbc_lblRfc.anchor = GridBagConstraints.EAST;
		gbc_lblRfc.insets = new Insets(0, 0, 5, 5);
		gbc_lblRfc.gridx = 0;
		gbc_lblRfc.gridy = 9;
		panel_8.add(lblRfc, gbc_lblRfc);
		
		textField_117 = new JTextField();
		GridBagConstraints gbc_textField_117 = new GridBagConstraints();
		gbc_textField_117.insets = new Insets(0, 0, 5, 5);
		gbc_textField_117.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_117.gridx = 1;
		gbc_textField_117.gridy = 9;
		panel_8.add(textField_117, gbc_textField_117);
		textField_117.setColumns(10);
		
		JLabel lblGfc = new JLabel("gfc");
		GridBagConstraints gbc_lblGfc = new GridBagConstraints();
		gbc_lblGfc.anchor = GridBagConstraints.EAST;
		gbc_lblGfc.insets = new Insets(0, 0, 5, 5);
		gbc_lblGfc.gridx = 0;
		gbc_lblGfc.gridy = 10;
		panel_8.add(lblGfc, gbc_lblGfc);
		
		textField_119 = new JTextField();
		GridBagConstraints gbc_textField_119 = new GridBagConstraints();
		gbc_textField_119.insets = new Insets(0, 0, 5, 5);
		gbc_textField_119.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_119.gridx = 1;
		gbc_textField_119.gridy = 10;
		panel_8.add(textField_119, gbc_textField_119);
		textField_119.setColumns(10);
		
		JLabel lblBfc = new JLabel("bfc");
		GridBagConstraints gbc_lblBfc = new GridBagConstraints();
		gbc_lblBfc.anchor = GridBagConstraints.EAST;
		gbc_lblBfc.insets = new Insets(0, 0, 0, 5);
		gbc_lblBfc.gridx = 0;
		gbc_lblBfc.gridy = 11;
		panel_8.add(lblBfc, gbc_lblBfc);
		
		textField_120 = new JTextField();
		GridBagConstraints gbc_textField_120 = new GridBagConstraints();
		gbc_textField_120.insets = new Insets(0, 0, 0, 5);
		gbc_textField_120.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField_120.gridx = 1;
		gbc_textField_120.gridy = 11;
		panel_8.add(textField_120, gbc_textField_120);
		textField_120.setColumns(10);
		
		tabbedPane.setSelectedIndex(0);

	}

}
