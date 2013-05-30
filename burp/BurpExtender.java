package burp;

// Awt
import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
// Swing
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import javax.swing.JButton;
import javax.swing.JList;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JComboBox;
import javax.swing.DefaultListModel;
import javax.swing.JCheckBox;
import javax.swing.BoxLayout;
import javax.swing.ListSelectionModel;
// Util
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
// IO
import java.io.PrintWriter;
// Net
import java.net.URL;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab, ActionListener
{
	private IExtensionHelpers helpers = null;
	private IBurpExtenderCallbacks callbacks = null;
	private JPanel mainPanel = null;

	private boolean isActive = false;
	private int method = 0;
	private JCheckBox enableCheckBox = null;
	private JTextField urlTextField = null;
	private JTextField paramTextField = null;
	private JTextArea logTextArea = null;
	private JList paramsList = null;
	private DefaultListModel paramsListModel = null;
	private JComboBox methodBox = null;

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("autoEdit");
		callbacks.registerHttpListener(this);

		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				mainPanel = new JPanel(new BorderLayout());
				mainPanel.setLayout(new BorderLayout());

				// North
				JPanel northPanel = new JPanel();
				northPanel.setLayout(new FlowLayout());
				enableCheckBox = new JCheckBox("disabled", isActive);
				enableCheckBox.setActionCommand("changestate");
				enableCheckBox.addActionListener(BurpExtender.this);
				urlTextField = new JTextField(40);
				urlTextField.setText("https?://www.google.fr/");
				northPanel.add(enableCheckBox);
				northPanel.add(new JLabel(" |  url (regex)  "));
				northPanel.add(urlTextField);
				JButton clearLogButton = new JButton("clear logs");
				clearLogButton.setActionCommand("clear_log");
				clearLogButton.addActionListener(BurpExtender.this);
				northPanel.add(clearLogButton);
				mainPanel.add(northPanel, BorderLayout.NORTH);

				// East
				JPanel eastPanel = new JPanel();
				eastPanel.setLayout(new BoxLayout(eastPanel, BoxLayout.PAGE_AXIS));
					// East-North
					JPanel eastNPanel = new JPanel();
					eastNPanel.setLayout(new FlowLayout());
					paramTextField = new JTextField(10);
					JButton addParamButton = new JButton("add");
					addParamButton.setActionCommand("add_param");
					addParamButton.addActionListener(BurpExtender.this);
					eastNPanel.add(paramTextField);
					eastNPanel.add(addParamButton);
				paramsListModel = new DefaultListModel();
				paramsList = new JList(paramsListModel);
				paramsList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
				paramsList.setVisibleRowCount(40);
					// East-South
					JPanel eastSPanel = new JPanel();
					eastSPanel.setLayout(new FlowLayout());
					JButton delParamButton = new JButton("del");
					delParamButton.setActionCommand("del_param");
					delParamButton.addActionListener(BurpExtender.this);
					JButton dellAllParamsButton = new JButton("del all");
					dellAllParamsButton.setActionCommand("del_all_params");
					dellAllParamsButton.addActionListener(BurpExtender.this);
					eastSPanel.add(delParamButton);
					eastSPanel.add(dellAllParamsButton);
				String[] methods =
				{
					"base64_encode",
					"base64_decode",
					"url_encode",
					"url_decode",
					"double_url_encode",
					"double_url_decode",
					"strange"
				};
				methodBox = new JComboBox(methods);
				methodBox.setSelectedIndex(0);
				eastPanel.add(new JLabel("- Parameters -"));
				eastPanel.add(eastNPanel);
				eastPanel.add(new JScrollPane(paramsList));
				eastPanel.add(eastSPanel);
				eastPanel.add(methodBox);

				// Center
				logTextArea = new JTextArea();
				logTextArea.setEditable(false);
				logTextArea.setAutoscrolls(true);
				logTextArea.setLineWrap(true);
				logTextArea.setFocusable(true);
				mainPanel.add(new JScrollPane(logTextArea), BorderLayout.CENTER);
				mainPanel.add(eastPanel, BorderLayout.EAST);

				callbacks.customizeUiComponent(mainPanel);
				callbacks.addSuiteTab(BurpExtender.this);
			}
		});
	}

	@Override
	public String getTabCaption()
	{
		return "autoEdit";
	}

	@Override
	public Component getUiComponent()
	{
		return this.mainPanel;
	}

	@Override
	public void actionPerformed(ActionEvent e)
	{
		if(e.getActionCommand().equals("add_param"))
		{
			if(!paramsListModel.contains(paramTextField.getText()))
			{
				paramsListModel.addElement(paramTextField.getText());
				paramTextField.setText("");
			}
		}
		if(e.getActionCommand().equals("del_param"))
		{
			int indexes[] = paramsList.getSelectedIndices();
			for(int i=indexes.length-1;i>=0;i--)
			{
				paramsListModel.remove(indexes[i]);
			}
		}
		if(e.getActionCommand().equals("del_all_params"))
		{
			paramsListModel.removeAllElements();
		}
		if(e.getActionCommand().equals("changestate"))
		{
			if(isActive)
			{
				isActive = false;
				enableCheckBox.setSelected(false);
				enableCheckBox.setText("disabled");
			}
			else
			{
				isActive = true;
				enableCheckBox.setSelected(true);
				enableCheckBox.setText("enabled");
			}
		}
		if(e.getActionCommand().equals("clear_log"))
		{
			logTextArea.setText("");
		}
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	{
		if(isActive && messageIsRequest)
		{
			IParameter parameter = helpers.getRequestParameter(messageInfo.getRequest(), paramTextField.getText());
			URL currentUrl = helpers.analyzeRequest(messageInfo).getUrl();
			Pattern pattern = Pattern.compile(urlTextField.getText(), Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
			String url1 = currentUrl.getProtocol()+"://"+currentUrl.getHost()+":"+currentUrl.getPort()+currentUrl.getPath()+"?"+currentUrl.getQuery();
			String url2 = currentUrl.getProtocol()+"://"+currentUrl.getHost()+currentUrl.getPath()+"?"+currentUrl.getQuery();
			if(pattern.matcher(url1).find() || pattern.matcher(url2).find())
			{
				// URL OK
				String curParamToChange = "";
				List<IParameter> listParams = helpers.analyzeRequest(messageInfo).getParameters();

				log("[+] URL : "+currentUrl.toString());
				for(int i=0;i<listParams.size();i++)
				{
					IParameter cur = listParams.get(i);
					if(paramsListModel.contains(cur.getName()))
					{
						// Current param OK
						String newValue = calNewValue(cur.getValue());
						IParameter newParameter = helpers.buildParameter(cur.getName(), newValue, cur.getType());
						byte[] newRequest = helpers.updateParameter(messageInfo.getRequest(), newParameter);
						messageInfo.setRequest(newRequest);
						log("  >> "+cur.getName()+":"+cur.getValue()+" -> "+cur.getName()+":"+newValue);
					}
				}
				log("");
			}
		}
	}

	// Next, some functions not overriden
	public String calNewValue(String value)
	{
		String methodS = (String)methodBox.getSelectedItem();
		if(methodS.equals("base64_encode"))
			return (new String(helpers.base64Encode(value.getBytes())));
		else if(methodS.equals("base64_decode"))
			return (new String(helpers.base64Decode(value.getBytes())));
		else if(methodS.equals("url_encode"))
			return helpers.urlEncode(value);
		else if(methodS.equals("url_decode"))
			return helpers.urlDecode(value);
		else if(methodS.equals("double_url_encode"))
			return helpers.urlEncode(helpers.urlEncode(value));
		else if(methodS.equals("double_url_decode"))
			return helpers.urlDecode(helpers.urlDecode(value));
		else if(methodS.equals("strange"))
		{
			String result = "";
			for(int i=0;i<value.length();i++)
				result = result + ((int)value.charAt(i)+64);
			result = helpers.base64Encode(result.getBytes());
			return result;
		}
		else
			return value;
	}
	
	public void log(String text)
	{
		logTextArea.append(text);
		logTextArea.append("\n");
		logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
	}
}
