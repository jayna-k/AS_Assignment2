using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AS_Assignment2.Migrations
{
    /// <inheritdoc />
    public partial class passwdHist : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "PasswordHistory",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "PasswordLastChanged",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: false,
                defaultValueSql: "GETUTCDATE()");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PasswordHistory",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "PasswordLastChanged",
                table: "AspNetUsers");
        }
    }
}
