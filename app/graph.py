import os
import sys
import tkinter as tk
from tkinter import messagebox, ttk

import matplotlib.pyplot as plt
import pandas as pd
import pyodbc
from scipy.stats import ttest_rel


class ExcelGraphApp:
    def __init__(self, root, patient_id):
        self.root = root
        self.root.title(f"Аналіз даних | Пацієнт {patient_id}")
        self.root.configure(bg="white")
        self.root.geometry("420x600")

        self.patient_id = patient_id
        self.patient_folder = os.path.join("patientexcels", str(patient_id))
        self.files = []
        self.data = {}
        self.graph_type = "Лінійний"

        default_font = ("Helvetica Neue", 12)
        bold_font = ("Helvetica Neue", 12, "bold")

        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "TButton", font=default_font, padding=6, relief="flat", background="#f0f0f0"
        )
        style.configure("TRadiobutton", font=default_font, background="white")
        style.configure("TLabel", font=default_font, background="white")
        style.configure("TFrame", background="white")

        if not os.path.exists(self.patient_folder):
            messagebox.showerror("Помилка", "Папка пацієнта не знайдена!")
            root.destroy()
            return

        main_frame = ttk.Frame(root, padding=10)
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(0, weight=1)

        ttk.Label(main_frame, text="Доступні файли", font=bold_font).grid(
            row=0, column=0, sticky="w"
        )
        self.file_listbox = tk.Listbox(
            main_frame,
            selectmode=tk.MULTIPLE,
            font=default_font,
            height=5,
            bd=1,
            relief="solid",
            highlightthickness=0,
        )
        self.file_listbox.grid(row=1, column=0, sticky="ew", pady=5)
        ttk.Button(main_frame, text="🔍 Вибрати файли", command=self.select_files).grid(
            row=2, column=0, pady=(0, 15)
        )

        self.load_files()

        ttk.Label(main_frame, text="Виберіть параметри:", font=bold_font).grid(
            row=3, column=0, sticky="w"
        )
        self.param_listbox = tk.Listbox(
            main_frame,
            selectmode=tk.MULTIPLE,
            height=4,
            font=default_font,
            bd=1,
            relief="solid",
            highlightthickness=0,
        )
        self.param_listbox.grid(row=4, column=0, sticky="ew", pady=5)

        ttk.Label(main_frame, text="Виберіть тип графіка:", font=bold_font).grid(
            row=5, column=0, sticky="w", pady=(10, 0)
        )

        self.graph_type_var = tk.StringVar(value="Лінійний")
        graph_frame = ttk.Frame(main_frame)
        graph_frame.grid(row=6, column=0, sticky="w")

        for i, text in enumerate(["Лінійний", "Стовпчаста", "Кругова"]):
            ttk.Radiobutton(
                graph_frame, text=text, variable=self.graph_type_var, value=text
            ).grid(row=i, column=0, sticky="w")

        self.plot_button = ttk.Button(
            main_frame,
            text="📊 Побудувати графік",
            command=self.plot_graph,
            state="disabled",
        )
        self.plot_button.grid(row=7, column=0, pady=15, sticky="ew")

        # === Середній пульс ===
        avg_pulse = self.get_average_pulse()
        if avg_pulse is not None:
            ttk.Label(
                main_frame, text=f"Середній пульс: {avg_pulse} уд/хв", font=bold_font
            ).grid(row=8, column=0, sticky="w", pady=(0, 10))
        else:
            ttk.Label(main_frame, text="Немає даних про пульс.", font=bold_font).grid(
                row=8, column=0, sticky="w", pady=(0, 10)
            )

        # === Статистика з БД ===
        ttk.Label(main_frame, text="Статистика з БД:", font=bold_font).grid(
            row=9, column=0, sticky="w", pady=(10, 0)
        )
        ttk.Button(
            main_frame, text="📉 Аналіз тиску", command=self.analyze_pressure
        ).grid(row=10, column=0, sticky="ew", pady=3)
        ttk.Button(
            main_frame, text="⚖️ Статистика ваги", command=self.analyze_weight
        ).grid(row=11, column=0, sticky="ew", pady=3)
        ttk.Button(
            main_frame, text="🧪 Ефект лікування", command=self.analyze_treatment_effect
        ).grid(row=12, column=0, sticky="ew", pady=(3, 10))

    def load_files(self):
        files = [
            f for f in os.listdir(self.patient_folder) if f.endswith((".xlsx", ".xls"))
        ]
        self.files = files
        self.file_listbox.delete(0, tk.END)
        for file in self.files:
            self.file_listbox.insert(tk.END, file)

    def select_files(self):
        selected_indices = self.file_listbox.curselection()
        selected_files = [self.files[i] for i in selected_indices]

        if not selected_files:
            return

        if self.graph_type_var.get() == "Кругова" and len(selected_files) > 1:
            messagebox.showwarning(
                "Помилка", "Для кругової діаграми можна вибрати лише один файл!"
            )
            return

        self.data = {}
        params = set()

        for file in selected_files:
            file_path = os.path.join(self.patient_folder, file)
            df = pd.read_excel(file_path, header=None)
            param_column = df.iloc[:, 0].dropna().tolist()
            self.data[file] = df
            params.update(param_column)

        self.param_listbox.delete(0, tk.END)
        for param in sorted(params):
            self.param_listbox.insert(tk.END, param)

        self.plot_button["state"] = "normal"

    def plot_graph(self):
        selected_indices = self.param_listbox.curselection()
        selected_params = [self.param_listbox.get(i) for i in selected_indices]
        selected_files = list(self.data.keys())

        if not selected_params:
            return

        graph_type = self.graph_type_var.get()

        if graph_type == "Кругова":
            if len(selected_files) != 1:
                messagebox.showwarning(
                    "Помилка", "Кругова діаграма підтримує лише один файл."
                )
                return

            file = selected_files[0]
            df = self.data[file]
            values, labels = [], []

            for param in selected_params:
                param_row = df[df.iloc[:, 0] == param]
                if not param_row.empty:
                    values.append(param_row.iloc[0, 1])
                    labels.append(param)

            if values:
                plt.figure(figsize=(6, 6))
                plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=140)
                plt.title(f"Кругова діаграма ({file})")
                plt.show()
            return

        plt.figure(figsize=(10, 5))

        if graph_type == "Лінійний":
            for param in selected_params:
                x_labels = []
                y_values = []
                for file in selected_files:
                    df = self.data[file]
                    param_row = df[df.iloc[:, 0] == param]
                    if not param_row.empty:
                        value = param_row.iloc[0, 1]
                        x_labels.append(file)
                        y_values.append(value)
                if y_values:
                    plt.plot(x_labels, y_values, marker="o", linestyle="-", label=param)

            plt.xlabel("Файл")
            plt.ylabel("Значення")
            plt.title("Лінійний графік")
            plt.legend()
            plt.grid(True)

        elif graph_type == "Стовпчаста":
            bar_width = 0.2
            x_indexes = range(len(selected_files))

            for i, param in enumerate(selected_params):
                values = []
                for file in selected_files:
                    df = self.data[file]
                    param_row = df[df.iloc[:, 0] == param]
                    if not param_row.empty:
                        values.append(param_row.iloc[0, 1])
                positions = [x + i * bar_width for x in x_indexes]
                plt.bar(positions, values, width=bar_width, label=param)

            plt.xlabel("Файл")
            plt.ylabel("Значення")
            plt.title("Стовпчаста діаграма")
            plt.xticks(
                [x + (len(selected_params) / 2) * bar_width for x in x_indexes],
                selected_files,
            )
            plt.legend()
            plt.grid(axis="y")

        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

    def get_average_pulse(self):
        try:
            db_path = os.path.abspath("medical_system.accdb")
            conn = pyodbc.connect(
                rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};"
            )
            cursor = conn.cursor()

            query = "SELECT pulse FROM pulse WHERE id = ?"
            cursor.execute(query, (self.patient_id,))
            pulses = [row[0] for row in cursor.fetchall() if row[0] is not None]

            conn.close()

            if pulses:
                return round(sum(pulses) / len(pulses), 2)
            return None
        except Exception as e:
            messagebox.showerror(
                "Помилка БД", f"Не вдалося підключитися до бази даних:\n{e}"
            )
            return None

    def analyze_pressure(self):
        try:
            db_path = os.path.abspath("medical_system.accdb")
            conn = pyodbc.connect(
                rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};"
            )
            df = pd.read_sql(
                f"SELECT bpressure, apressure FROM Pressure WHERE id = {self.patient_id}",
                conn,
            )
            conn.close()

            if df.empty:
                messagebox.showinfo("Немає даних", "Немає даних про тиск.")
                return

            bp_all = df["bpressure"].dropna()
            ap_all = df["apressure"].dropna()

            msg = ""
            if not bp_all.empty:
                msg += f"📌 Початковий тиск:\n - Дисперсія: {bp_all.var():.2f}\n - Відхилення: {bp_all.std():.2f}\n"
            if not ap_all.empty:
                msg += f"\n📌 Після лікування:\n - Дисперсія: {ap_all.var():.2f}\n - Відхилення: {ap_all.std():.2f}"

            messagebox.showinfo("Стабільність тиску", msg)
        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    def analyze_weight(self):
        try:
            db_path = os.path.abspath("medical_system.accdb")
            conn = pyodbc.connect(
                rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};"
            )
            df = pd.read_sql(
                f"SELECT weight, sugar FROM WaS WHERE id = {self.patient_id}", conn
            )
            conn.close()

            if df.empty:
                messagebox.showinfo("Немає даних", "Немає даних про вагу/цукор.")
                return

            # Функция для преобразования дроби из текста в float
            def parse_fraction(fraction_str):
                try:
                    if "/" in fraction_str:
                        num, denom = fraction_str.split("/")
                        return float(num) / float(denom)
                    else:
                        return float(fraction_str)
                except:
                    return None  # неверный формат — пропускаем

            # Преобразуем текстовые дроби в числовые значения
            df["ParsedSugar"] = df["Sugar"].apply(parse_fraction)

            # Удалим строки с None
            df = df.dropna(subset=["Weight", "ParsedSugar"])

            if df.empty:
                messagebox.showinfo(
                    "Недостатньо даних", "Немає коректних значень цукру."
                )
                return

            weight_median = df["Weight"].median()
            corr = df["Weight"].corr(df["ParsedSugar"])

            messagebox.showinfo(
                "Аналіз ваги",
                f"📏 Медіана ваги: {weight_median:.2f}\n"
                f"🔗 Кореляція ваги і цукру: {corr:.2f}",
            )
        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    def analyze_treatment_effect(self):
        try:
            db_path = os.path.abspath("medical_system.accdb")
            conn = pyodbc.connect(
                rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};"
            )
            df = pd.read_sql(
                f"SELECT bpressure, apressure FROM Pressure WHERE id = {self.patient_id}",
                conn,
            )
            conn.close()

            before = df["bpressure"].dropna()
            after = df["apressure"].dropna()

            if len(before) != len(after) or len(before) < 2:
                messagebox.showwarning(
                    "Недостатньо даних", "Потрібно хоча б 2 пари значень тиску."
                )
                return

            t_stat, p_value = ttest_rel(before, after)

            msg = f"📊 T-критерій Стьюдента:\nT = {t_stat:.3f}, p = {p_value:.3f}\n"
            if p_value < 0.05:
                msg += "✅ Є статистично значущий ефект."
            else:
                msg += "ℹ️ Ефект статистично незначущий."

            messagebox.showinfo("Ефект лікування", msg)
        except Exception as e:
            messagebox.showerror("Помилка", str(e))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("⚠️ Помилка: потрібно передати ID пацієнта.")
        sys.exit(1)

    patient_id = sys.argv[1]
    root = tk.Tk()
    app = ExcelGraphApp(root, patient_id)
    root.mainloop()
