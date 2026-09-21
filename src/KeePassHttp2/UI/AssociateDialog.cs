// Minimal "allow this client to pair?" prompt. Shown on the KeePass UI
// thread (via MainWindow.Invoke) when a client calls "associate" - this
// dialog IS the actual trust boundary for the whole protocol: any client
// can freely do change-public-keys, but nothing beyond that succeeds
// until a human clicks Allow here. Matches the KeePassHttp/KeePassXC UX
// of picking a name to remember the pairing by.

using System.Drawing;
using System.Windows.Forms;

namespace KeePassHttp2.UI;

internal sealed class AssociateDialog : Form
{
    private readonly TextBox _nameBox;

    public string ChosenName => _nameBox.Text.Trim();

    public AssociateDialog(string suggestedName)
    {
        Text = "KeePassHttp2 - New connection request";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false;
        MaximizeBox = false;
        ClientSize = new Size(360, 120);

        var label = new Label
        {
            Text = "A new application is requesting access to this database.\n" +
                   "Enter a name to allow and remember it:",
            AutoSize = false,
            Location = new Point(12, 12),
            Size = new Size(336, 40),
        };

        _nameBox = new TextBox
        {
            Text = suggestedName,
            Location = new Point(12, 56),
            Size = new Size(336, 23),
        };

        var allowButton = new Button
        {
            Text = "Allow",
            DialogResult = DialogResult.OK,
            Location = new Point(192, 86),
            Size = new Size(75, 25),
        };

        var denyButton = new Button
        {
            Text = "Deny",
            DialogResult = DialogResult.Cancel,
            Location = new Point(273, 86),
            Size = new Size(75, 25),
        };

        Controls.Add(label);
        Controls.Add(_nameBox);
        Controls.Add(allowButton);
        Controls.Add(denyButton);

        AcceptButton = allowButton;
        CancelButton = denyButton;
    }
}