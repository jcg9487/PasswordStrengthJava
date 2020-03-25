
import java.util.Scanner;

public class PWDChecker {
    static final String sAlphas = "abcdefghijklmnopqrstuvwxyz";
    static final String sNumerics = "01234567890";
    static final String sSymbols = ")!@#$%^&*()";

    static final int nMultRepChar = 1, nMultConsecSymbol = 1;
    static final int nMultMidChar = 2, nMultRequirements = 2, nMultConsecAlphaUC = 2, nMultConsecAlphaLC = 2, nMultConsecNumber = 2;
    static final int nReqCharType = 3, nMultAlphaUC = 3, nMultAlphaLC = 3, nMultSeqAlpha = 3, nMultSeqNumber = 3, nMultSeqSymbol = 3;
    static final int nMultLength = 4, nMultNumber = 4;
    static final int nMultSymbol = 6;

    private String reverse(String value) {
        return new StringBuffer(value).reverse().toString();
    }

    private boolean isEmpty(String value) {
        return value == null || "".equals(value);
    }

    private boolean equals(String value1, String value2) {
        return value1.equals(value2);
    }

    private void printScro(String pre, int score) {
        System.out.println(pre + ":" + score);
    }

    private int chkPass(String pwd) {
        int nScore = 0, nLength = 0, nAlphaUC = 0, nAlphaLC = 0, nNumber = 0, nSymbol = 0, nMidChar = 0,
                nRequirements = 0, nAlphasOnly = 0, nNumbersOnly = 0, nUnqChar = 0,
                nRepChar = 0, nConsecAlphaUC = 0, nConsecAlphaLC = 0,
                nConsecNumber = 0, nConsecSymbol = 0, nConsecCharType = 0, nSeqAlpha = 0,
                nSeqNumber = 0, nSeqSymbol = 0, nSeqChar = 0, nReqChar = 0, nMultConsecCharType = 0;

        double nRepInc = 0f;

        // Simultaneous variable declaration and value assignment aren't supported in IE apparently
        // so I'm forced to assign the same value individually per var to support a crappy browser *sigh*

        Integer nTmpAlphaUC = null, nTmpAlphaLC = null, nTmpNumber = null, nTmpSymbol = null;
        String sComplexity = "Too Short";
        String sStandards = "Below";
        int nMinPwdLen = 8;
//        if (document.all) { var nd = 0; } else { var nd = 1; }
        if (!isEmpty(pwd)) {
            nScore = pwd.length() * nMultLength;
            printScro("密码长度", nScore);
            nLength = pwd.length();
            String[] arrPwd = pwd.replaceAll("\\s+/g", "").split("\\s*");
            int arrPwdLen = arrPwd.length;

            /* Loop through password to check for Symbol, Numeric, Lowercase and Uppercase pattern matches */
            for (int a = 0; a < arrPwdLen; a++) {
                if (arrPwd[a].matches("[A-Z]")) {
                    if (nTmpAlphaUC != null) {
                        if (nTmpAlphaUC + 1 == a) {
                            nConsecAlphaUC++;
                            nConsecCharType++;
                        }
                    }
                    nTmpAlphaUC = a;
                    nAlphaUC++;
                } else if (arrPwd[a].matches("[a-z]")) {
                    if (nTmpAlphaLC != null) {
                        if (nTmpAlphaLC + 1 == a) {
                            nConsecAlphaLC++;
                            nConsecCharType++;
                        }
                    }
                    nTmpAlphaLC = a;
                    nAlphaLC++;
                } else if (arrPwd[a].matches("[0-9]")) {
                    if (a > 0 && a < (arrPwdLen - 1)) {
                        nMidChar++;
                    }
                    if (nTmpNumber != null) {
                        if (nTmpNumber + 1 == a) {
                            nConsecNumber++;
                            nConsecCharType++;
                        }
                    }
                    nTmpNumber = a;
                    nNumber++;
                } else if (arrPwd[a].matches("[^a-zA-Z0-9_]")) {
                    if (a > 0 && a < (arrPwdLen - 1)) {
                        nMidChar++;
                    }
                    if (nTmpSymbol != null) {
                        if (nTmpSymbol + 1 == a) {
                            nConsecSymbol++;
                            nConsecCharType++;
                        }
                    }
                    nTmpSymbol = a;
                    nSymbol++;
                }
                /* Internal loop through password to check for repeat characters */
                boolean bCharExists = false;
                for (int b = 0; b < arrPwdLen; b++) {
                    if (equals(arrPwd[a], arrPwd[b]) && a != b) { /* repeat character exists */
                        bCharExists = true;
					/*
					Calculate icrement deduction based on proximity to identical characters
					Deduction is incremented each time a new match is discovered
					Deduction amount is based on total password length divided by the
					difference of distance between currently selected match
					*/
                        nRepInc += Math.abs(arrPwdLen * 1.0 / (b - a));
                    }
                }
                if (bCharExists) {
                    nRepChar++;
                    nUnqChar = arrPwdLen - nRepChar;
                    nRepInc = (nUnqChar != 0) ? Math.ceil(nRepInc / nUnqChar) : Math.ceil(nRepInc);
                }
            }

            /* Check for sequential alpha string patterns (forward and reverse) */
            //TODO 连续字母
            for (int s = 0; s < 23; s++) {
                String sFwd = sAlphas.substring(s, s + 3);
                String sRev = reverse(sFwd);
                if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) {
                    nSeqAlpha++;
                    nSeqChar++;
                }
            }

            /* Check for sequential numeric string patterns (forward and reverse) */
            for (int s = 0; s < 8; s++) {
                String sFwd = sNumerics.substring(s, s + 3);
                String sRev = reverse(sFwd);
                if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) {
                    nSeqNumber++;
                    nSeqChar++;
                }
            }

            /* Check for sequential symbol string patterns (forward and reverse) */
            for (int s = 0; s < 8; s++) {
                String sFwd = sSymbols.substring(s, s + 3);
                String sRev = reverse(sFwd);
                if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) {
                    nSeqSymbol++;
                    nSeqChar++;
                }
            }

            /* Modify overall score value based on usage vs requirements */
            /* General point assignment */
            //TODO 加分项
            //TODO 密码长度
            if (nAlphaUC > 0 && nAlphaUC < nLength) {
                int tempScore = (nLength - nAlphaUC) * 2;
                nScore = nScore + tempScore;
                printScro("大写字母 :", tempScore);
                //TODO 大写字母
            }
            if (nAlphaLC > 0 && nAlphaLC < nLength) {
                int tempScore = (nLength - nAlphaLC) * 2;
                nScore = nScore + tempScore;
                //TODO 小写字母
                printScro("小写字母 :", tempScore);
            }
            if (nNumber > 0 && nNumber < nLength) {
                int tempScore = (nNumber * nMultNumber);
                nScore = nScore + tempScore;
                //TODO 数字字符
                printScro("数字 :", tempScore);
            }
            if (nSymbol > 0) {
                int tempScore = (nSymbol * nMultSymbol);
                nScore = nScore + tempScore;
                //TODO 特殊符号
                printScro("特殊符号 :", tempScore);
            }
            if (nMidChar > 0) {
                int tempScore = (nMidChar * nMultMidChar);
                nScore = nScore + tempScore;
                //TODO 密码中间包含该数字或特殊符号
                printScro("密码中间包含该数字或特殊符号 :", tempScore);
            }

            //TODO 扣分项
            /* Point deductions for poor practices */
            if ((nAlphaLC > 0 || nAlphaUC > 0) && nSymbol == 0 && nNumber == 0) {  // Only Letters
                //TODO 只有大小写字母
                nScore = nScore - nLength;
                nAlphasOnly = nLength;
                printScro("只有小写字母 :", -nLength);
            }
            if (nAlphaLC == 0 && nAlphaUC == 0 && nSymbol == 0 && nNumber > 0) {  // Only Numbers
                //TODO 只有数字
                nScore = nScore - nLength;
                nNumbersOnly = nLength;
                printScro("自有数字 :", -nLength);
            }
            if (nRepChar > 0) {  // Same character exists more than once
                //TODO 重复字符
                nScore = nScore - (int) nRepInc;
                printScro("重复字符 (区分大小写) :", (int) -nRepInc);
            }
            if (nConsecAlphaUC > 0) {  // Consecutive Uppercase Letters exist
                //TODO 连续大写字母
                int tempScore = nConsecAlphaUC * nMultConsecAlphaUC;
                nScore = nScore - tempScore;
                printScro("连续大写字母 :", -tempScore);
            }
            if (nConsecAlphaLC > 0) {  // Consecutive Lowercase Letters exist
                int tempScore = nConsecAlphaLC * nMultConsecAlphaLC;
                //TODO 连续小写字母
                nScore = nScore - tempScore;
                printScro("连续小写字母 :", -tempScore);
            }
            if (nConsecNumber > 0) {  // Consecutive Numbers exist
                int tempScore = nConsecNumber * nMultConsecNumber;
                //TODO 连续数字
                nScore = nScore - tempScore;
                printScro("连续数字 :", -tempScore);
            }
            if (nSeqAlpha > 0) {  // Sequential alpha strings exist (3 characters or more)
                int tempScore = (nSeqAlpha * nMultSeqAlpha);
                //TODO 超过三个连续字母(如abc,def,hij)
                nScore = nScore - tempScore;
                printScro("超过三个连续字母(如abc,def,hij) :", -tempScore);
            }
            if (nSeqNumber > 0) {  // Sequential numeric strings exist (3 characters or more)
                int tempScore = (nSeqNumber * nMultSeqNumber);
                //TODO  	超过三个连续数字(如123，567)
                nScore = nScore - tempScore;
                printScro("超过三个连续数字(如123，567):", -tempScore);
            }
            if (nSeqSymbol > 0) {  // Sequential symbol strings exist (3 characters or more)
                int tempScore = (nSeqSymbol * nMultSeqSymbol);
                //TODO 	超过三个连续特殊字符(如!@#,^&*)
                nScore = nScore - tempScore;
                printScro("超过三个连续特殊字符(如!@#,^&*) :", -tempScore);
            }

            /* Determine if mandatory requirements have been met and set image indicators accordingly */
            int[] arrChars = {nLength, nAlphaUC, nAlphaLC, nNumber, nSymbol};
            String[] arrCharsIds = {"nLength", "nAlphaUC", "nAlphaLC", "nNumber", "nSymbol"};
            int arrCharsLen = arrChars.length;
            for (int c = 0; c < arrCharsLen; c++) {
                int minVal;
                if (arrCharsIds[c] == "nLength") {
                    minVal = nMinPwdLen - 1;
                } else {
                    minVal = 0;
                }
                if (arrChars[c] == minVal + 1) {
                    nReqChar++;
                } else if (arrChars[c] > minVal + 1) {
                    nReqChar++;
                } else {
                }
            }
            nRequirements = nReqChar;

            int nMinReqChars = 0;
            if (pwd.length() >= nMinPwdLen) {
                nMinReqChars = 3;
            } else {
                nMinReqChars = 4;
            }

            if (nRequirements > nMinReqChars) {  // One or more required characters exist
                int tempScore = nRequirements * 2;
                nScore = nScore + tempScore;
                //TODO 已达到最低要求项目
                printScro("已达到最低要求项目 :", tempScore);
            }


            /* Determine complexity based on overall score */
            if (nScore > 100) {
                nScore = 100;
            } else if (nScore < 0) {
                nScore = 0;
            }

            System.out.println("nScore: " + nScore);

            if (nScore >= 0 && nScore < 20) {
                sComplexity = "Very Weak ";
            } else if (nScore >= 20 && nScore < 40) {
                sComplexity = "Weak";
            } else if (nScore >= 40 && nScore < 60) {
                sComplexity = "Good";
            } else if (nScore >= 60 && nScore < 80) {
                sComplexity = "Strong";
            } else if (nScore >= 80 && nScore <= 100) {
                sComplexity = "Very Strong";
            }

            System.out.println(sComplexity);
        } else {
            System.out.println(sComplexity);
        }

        return nScore;
    }

    public static void main(String[] args) {

        PWDChecker pwdChecker = new PWDChecker();
//        new PWDChecker().chkPass("abcdefg");
//        new PWDChecker().chkPass("jjsdfs2323");//重复 -3 -4
//        new PWDChecker().chkPass("jhyG68&3@");
//        new PWDChecker().chkPass("5778194923");//重复 0 -1
//        new PWDChecker().chkPass("oosdfsksd");//重复 -1 -3
//        new PWDChecker().chkPass("ffsdfsaAdds");//重复 -4 -5
//        new PWDChecker().chkPass("898923sdsd");
//        new PWDChecker().chkPass("%8#aaf3&87$3*");

        Scanner scanner = new Scanner(System.in);

        String readV = null;
        do {
            readV = scanner.next();
            pwdChecker.chkPass(readV);
        } while (!"exit".equals(readV));
    }
}
