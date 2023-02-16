"""add_app_header_table
Revision ID: c6e491604237
Revises: d22f27fbeaad
Create Date: 2023-02-16 17:00:40.817595
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "c6e491604237"
down_revision = "d22f27fbeaad"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "application_header",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("remote", sa.Boolean(), nullable=True),
        sa.Column("cluster_id", sa.Integer(), nullable=True),
        sa.Column("registry_id", sa.Integer(), nullable=True),
        sa.Column("namespace", sa.String(), nullable=True),
        sa.Column("applications_id", sa.String(), nullable=True),
        sa.Column("disabled", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["cluster_id"],
            ["cluster.id"],
        ),
        sa.ForeignKeyConstraint(
            ["registry_id"],
            ["registries.registries_id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute(
        """
        insert into application_header (name, remote, cluster_id, registry_id, namespace, applications_id, disabled, created_at, updated_at)
        select name, case when cluster_id=0 and registry_id=0 then False else true end as remote, cluster_id, registry_id, namespace, '[' || array_to_string(array_agg(id), ',') || ']' as applications_id, false as disabled, min(created_at) as created_at, max(updated_at) as updated_at
        from application a
        group by name, namespace, cluster_id, registry_id
    """
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("application_header")
    # ### end Alembic commands ###
