﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using Microsoft.Tools.WindowsInstallerXml;

namespace PanelSw.Wix.Extensions
{
    class PanelSwPreProcessor : PreprocessorExtension
    {
        private string[] prefixes_ = new string[] { "tuple", "endtuple" };
        public override string[] Prefixes => prefixes_;

        Dictionary<string, List<string>> tuples_ = new Dictionary<string, List<string>>();
        public override void FinalizePreprocess()
        {
            tuples_.Clear();
        }

        public override void InitializePreprocess()
        {
            tuples_.Clear();
        }

        public override bool ProcessPragma(SourceLineNumberCollection sourceLineNumbers, string prefix, string pragma, string args, XmlWriter writer)
        {
            switch (prefix)
            {
                case "tuple":
                    if (tuples_.ContainsKey(pragma))
                    {
                        throw new WixException(WixErrors.PreprocessorExtensionPragmaFailed(sourceLineNumbers, pragma, "Pragma is nested within same pragma"));
                    }

                    List<string> values = new List<string>(args.Split(';'));
                    if (values.Count == 0)
                    {
                        throw new WixException(WixErrors.PreprocessorExtensionPragmaFailed(sourceLineNumbers, pragma, "No values specified. Expected '<?pragma tuple.KEY val1;val2;...;valX?>'"));
                    }

                    tuples_[pragma] = values;
                    return true;

                case "endtuple":
                    if (!tuples_.Remove(pragma))
                    {
                        throw new WixException(WixErrors.PreprocessorExtensionPragmaFailed(sourceLineNumbers, pragma, $"endtuple pragma for undefined tuple"));
                    }
                    return true;

                default:
                    return false;
            }
        }

        public override string EvaluateFunction(string prefix, string key, string[] args)
        {
            if (!prefix.Equals("tuple"))
            {
                return null;
            }

            if (!tuples_.ContainsKey(key))
            {
                return null;
            }

            if (args.Length != 1)
            {
                return null;
            }

            int i;
            if (!int.TryParse(args[0], out i) || (i < 0) || (i >= tuples_[key].Count))
            {
                return null;
            }

            return tuples_[key][i];
        }

        public override string GetVariableValue(string prefix, string name)
        {
            if (!prefix.Equals("tuple"))
            {
                return null;
            }

            int i = name.LastIndexOf('.');
            if (i <= 1)
            {
                return null;
            }

            string key = name.Substring(0, i);
            string arg = name.Substring(i + 1);

            return EvaluateFunction(prefix, key, new string[] { arg });
        }
    }
}