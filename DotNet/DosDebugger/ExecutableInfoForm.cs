using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using Disassembler;

namespace DosDebugger
{
    public partial class ExecutableInfoForm : Form
    {
        public ExecutableInfoForm()
        {
            InitializeComponent();
        }

        public MZFile MzFile
        {
            get { return (MZFile)propertyGrid1.SelectedObject; }
            set { propertyGrid1.SelectedObject = value; }
        }

        private void ExecutableInfoForm_Load(object sender, EventArgs e)
        {

        }
    }
}
